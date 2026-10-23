"""UNIX-domain socket server for ssh-agent implementation."""
import contextlib
import hmac
import logging
import os
import socket
import subprocess
import threading

from . import util

log = logging.getLogger(__name__)


def remove_file(path, remove=os.remove, exists=os.path.exists):
    """Remove file, and raise OSError if still exists."""
    try:
        remove(path)
    except OSError:
        if exists(path):
            raise


@contextlib.contextmanager
def unix_domain_socket_server(sock_path):
    """
    Create UNIX-domain socket on specified path.

    Listen on it, and delete it after the generated context is over.
    """
    log.debug('serving on %s', sock_path)
    remove_file(sock_path)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    try:
        yield server
    finally:
        remove_file(sock_path)


class FDServer:
    """File-descriptor based server (for NeoPG)."""

    def __init__(self, fd):
        """C-tor."""
        self.fd = fd
        self.sock = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)

    def accept(self):
        """Use the same socket for I/O."""
        return self, None

    def recv(self, n):
        """Forward to underlying socket."""
        return self.sock.recv(n)

    def sendall(self, data):
        """Forward to underlying socket."""
        return self.sock.sendall(data)

    def close(self):
        """Not needed."""

    def settimeout(self, _):
        """Not needed."""

    def getsockname(self):
        """Simple representation."""
        return '<fd: {}>'.format(self.fd)


@contextlib.contextmanager
def unix_domain_socket_server_from_fd(fd):
    """Build UDS-based socket server from a file descriptor."""
    yield FDServer(fd)


ASSUAN_NONCE_LEN = 16


class AssuanNonceServer:
    """
    libassuan's socket emulation, as GnuPG for Windows uses it.

    The socket "file" holds a TCP port on 127.0.0.1, a newline, and a 16-byte
    nonce. A client connects to the port and must send the nonce before
    anything else; a connection that does not is dropped. The nonce is what
    keeps other local users out, and the file's place in the user's own
    profile is what keeps the nonce from them.
    """

    def __init__(self, sock, nonce):
        """C-tor."""
        self.sock = sock
        self.nonce = nonce

    def accept(self):
        """Wait for a connection that starts with the nonce."""
        while True:
            conn, addr = self.sock.accept()
            conn.settimeout(10)  # a silent client must not block the agent
            received = b''
            try:
                while len(received) < ASSUAN_NONCE_LEN:
                    chunk = conn.recv(ASSUAN_NONCE_LEN - len(received))
                    if not chunk:
                        break
                    received += chunk
            except OSError:
                pass
            if hmac.compare_digest(received, self.nonce):
                return conn, addr
            log.warning('dropping a connection without the socket nonce')
            conn.close()

    def getsockname(self):
        """Forward to underlying socket."""
        return self.sock.getsockname()


@contextlib.contextmanager
def assuan_nonce_socket_server(sock_path):
    """
    Serve libassuan's Windows socket emulation at the specified path.

    Listen on a loopback port, write the port and a fresh nonce to sock_path,
    and delete the file after the generated context is over.
    """
    log.debug('serving on %s', sock_path)
    remove_file(sock_path)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    nonce = os.urandom(ASSUAN_NONCE_LEN)
    with open(sock_path, 'wb') as f:
        f.write('{}\n'.format(server.getsockname()[1]).encode('ascii') + nonce)
    try:
        yield AssuanNonceServer(server, nonce)
    finally:
        server.close()
        remove_file(sock_path)


WINDOWS_PIPE_BUFSIZE = 65536


class NamedPipeConnection:
    """
    One client of a Windows named pipe, with the calls the agent makes on a socket.

    Overlapped I/O, because the pipe is opened overlapped (so accept() can time out).
    """

    def __init__(self, handle):
        """C-tor."""
        self.handle = handle

    def recv(self, n):
        """Read up to n bytes; b'' when the client has gone (the agent's EOF)."""
        import _winapi  # pylint: disable=import-outside-toplevel,import-error
        try:
            ov, err = _winapi.ReadFile(self.handle, n, overlapped=True)
        except OSError as e:
            if getattr(e, 'winerror', None) == _winapi.ERROR_BROKEN_PIPE:
                return b''
            raise
        try:
            if err == _winapi.ERROR_IO_PENDING:
                _winapi.WaitForMultipleObjects([ov.event], False, _winapi.INFINITE)
        except BaseException:
            ov.cancel()
            raise
        try:
            nread, err = ov.GetOverlappedResult(True)
        except OSError as e:
            if getattr(e, 'winerror', None) == _winapi.ERROR_BROKEN_PIPE:
                return b''
            raise
        return bytes(ov.getbuffer()[:nread])

    def sendall(self, data):
        """Write all of data."""
        import _winapi  # pylint: disable=import-outside-toplevel,import-error
        ov, err = _winapi.WriteFile(self.handle, data, overlapped=True)
        try:
            if err == _winapi.ERROR_IO_PENDING:
                _winapi.WaitForMultipleObjects([ov.event], False, _winapi.INFINITE)
        except BaseException:
            ov.cancel()
            raise
        nwritten, err = ov.GetOverlappedResult(True)
        if nwritten != len(data):
            raise OSError('short write to the agent pipe: {} of {}'.format(nwritten, len(data)))

    def settimeout(self, _):
        """Not needed: the agent waits on a client for as long as it stays."""

    def close(self):
        """Close this client's pipe instance."""
        import _winapi  # pylint: disable=import-outside-toplevel,import-error
        if self.handle is not None:
            _winapi.CloseHandle(self.handle)
            self.handle = None


class NamedPipeServer:
    """
    An ssh-agent listener on a Windows named pipe - what Windows' OpenSSH looks for.

    CPython on Windows has no socket.AF_UNIX, so the UNIX-domain server cannot
    start there. Each accept() serves one pipe instance (byte mode) and makes the
    next. Remote clients are rejected (PIPE_REJECT_REMOTE_CLIENTS), and the first
    instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE, so a name another
    process already holds fails at start instead of letting it impersonate the
    agent. The pipe has Windows' default security for a named pipe: only this
    user, SYSTEM and Administrators may write to it.
    """

    PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
    # Win32's byte-mode flags are 0, and _winapi does not name them; spelled out
    # so the mode is visible: a byte stream, as ssh writes it, not messages.
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_READMODE_BYTE = 0x00000000

    def __init__(self, name):
        """C-tor."""
        self.name = name
        self.timeout = None
        self._pending = None   # (handle, overlapped) waiting for a client
        self._first = True

    def _listen(self):
        import _winapi  # pylint: disable=import-outside-toplevel,import-error
        open_mode = _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_OVERLAPPED
        if self._first:
            open_mode |= _winapi.FILE_FLAG_FIRST_PIPE_INSTANCE
        handle = _winapi.CreateNamedPipe(
            self.name, open_mode,
            self.PIPE_TYPE_BYTE | self.PIPE_READMODE_BYTE | _winapi.PIPE_WAIT
            | self.PIPE_REJECT_REMOTE_CLIENTS,
            _winapi.PIPE_UNLIMITED_INSTANCES, WINDOWS_PIPE_BUFSIZE, WINDOWS_PIPE_BUFSIZE,
            _winapi.NMPWAIT_WAIT_FOREVER, _winapi.NULL)
        self._first = False
        try:
            ov = _winapi.ConnectNamedPipe(handle, overlapped=True)
        except OSError:
            _winapi.CloseHandle(handle)
            raise
        self._pending = (handle, ov)

    def start(self):
        """Create the first instance now, so a taken name fails before anything runs."""
        self._listen()

    def settimeout(self, timeout):
        """How long accept() waits before raising socket.timeout (None: forever)."""
        self.timeout = timeout

    def accept(self):
        """Wait for a client on the pending instance; raise socket.timeout if none came."""
        import _winapi  # pylint: disable=import-outside-toplevel,import-error
        if self._pending is None:
            self._listen()
        handle, ov = self._pending
        wait_ms = _winapi.INFINITE if self.timeout is None else int(self.timeout * 1000)
        if _winapi.WaitForMultipleObjects([ov.event], False, wait_ms) == _winapi.WAIT_TIMEOUT:
            raise socket.timeout()
        self._pending = None
        try:
            ov.GetOverlappedResult(True)
        except OSError as e:
            # ERROR_NO_DATA: the client connected and left already - nothing to serve
            _winapi.CloseHandle(handle)
            if getattr(e, 'winerror', None) == _winapi.ERROR_NO_DATA:
                raise socket.timeout() from e
            raise
        return NamedPipeConnection(handle), None

    def getsockname(self):
        """The pipe's name."""
        return self.name

    def close(self):
        """Stop listening."""
        import _winapi  # pylint: disable=import-outside-toplevel,import-error
        if self._pending is not None:
            handle, ov = self._pending
            self._pending = None
            ov.cancel()
            _winapi.CloseHandle(handle)


@contextlib.contextmanager
def named_pipe_server(pipe_name):
    r"""
    Serve the ssh-agent on a Windows named pipe (e.g. \\.\pipe\onlykey-agent-...).

    The Windows counterpart of unix_domain_socket_server(); the pipe goes away
    when the generated context is over.
    """
    log.debug('serving on %s', pipe_name)
    pipe_server = NamedPipeServer(pipe_name)
    pipe_server.start()
    try:
        yield pipe_server
    finally:
        pipe_server.close()


def handle_connection(conn, handler, mutex):
    """
    Handle a single connection using the specified protocol handler in a loop.

    Since this function may be called concurrently from server_thread,
    the specified mutex is used to synchronize the device handling.

    Exit when EOFError is raised.
    All other exceptions are logged as warnings.
    """
    try:
        log.debug('welcome agent')
        with contextlib.closing(conn):
            while True:
                msg = util.read_frame(conn)
                with mutex:
                    reply = handler.handle(msg=msg)
                util.send(conn, reply)
    except EOFError:
        log.debug('goodbye agent')
    except Exception as e:  # pylint: disable=broad-except
        log.warning('error: %s', e, exc_info=True)


def retry(func, exception_type, quit_event):
    """
    Run the function, retrying when the specified exception_type occurs.

    Poll quit_event on each iteration, to be responsive to an external
    exit request.
    """
    while True:
        if quit_event.is_set():
            raise StopIteration
        try:
            return func()
        except exception_type:
            pass


def server_thread(sock, handle_conn, quit_event):
    """Run a server on the specified socket."""
    log.debug('server thread started')

    def accept_connection():
        conn, _ = sock.accept()
        conn.settimeout(None)
        return conn

    while True:
        log.debug('waiting for connection on %s', sock.getsockname())
        try:
            conn = retry(accept_connection, socket.timeout, quit_event)
        except StopIteration:
            log.debug('server stopped')
            break
        # Handle connections from SSH concurrently.
        threading.Thread(target=handle_conn,
                         kwargs={'conn': conn}).start()
    log.debug('server thread stopped')


@contextlib.contextmanager
def spawn(func, kwargs):
    """Spawn a thread, and join it after the context is over."""
    t = threading.Thread(target=func, kwargs=kwargs)
    t.start()
    yield
    t.join()


def run_process(command, environ):
    """
    Run the specified process and wait until it finishes.

    Use environ dict for environment variables.
    """
    log.info('running %r with %r', command, environ)
    env = dict(os.environ)
    env.update(environ)
    try:
        p = subprocess.Popen(args=command, env=env)
    except OSError as e:
        raise OSError('cannot run %r: %s' % (command, e)) from e
    log.debug('subprocess %d is running', p.pid)
    ret = p.wait()
    log.debug('subprocess %d exited: %d', p.pid, ret)
    return ret
