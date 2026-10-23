import io
import os
import socket
import sys
import tempfile
import threading

import mock
import pytest

from .. import server, util
from ..ssh import protocol


def test_socket():
    path = tempfile.mktemp()
    with server.unix_domain_socket_server(path):
        pass
    assert not os.path.isfile(path)


class FakeSocket:

    def __init__(self, data=b''):
        self.rx = io.BytesIO(data)
        self.tx = io.BytesIO()

    def sendall(self, data):
        self.tx.write(data)

    def recv(self, size):
        return self.rx.read(size)

    def close(self):
        pass

    def settimeout(self, value):
        pass


def empty_device():
    c = mock.Mock(spec=['parse_public_keys'])
    c.parse_public_keys.return_value = []
    return c


def test_handle():
    mutex = threading.Lock()

    handler = protocol.Handler(conn=empty_device())
    conn = FakeSocket()
    server.handle_connection(conn, handler, mutex)

    msg = bytearray([protocol.msg_code('SSH_AGENTC_REQUEST_RSA_IDENTITIES')])
    conn = FakeSocket(util.frame(msg))
    server.handle_connection(conn, handler, mutex)
    assert conn.tx.getvalue() == b'\x00\x00\x00\x05\x02\x00\x00\x00\x00'

    msg = bytearray([protocol.msg_code('SSH2_AGENTC_REQUEST_IDENTITIES')])
    conn = FakeSocket(util.frame(msg))
    server.handle_connection(conn, handler, mutex)
    assert conn.tx.getvalue() == b'\x00\x00\x00\x05\x0C\x00\x00\x00\x00'

    msg = bytearray([protocol.msg_code('SSH2_AGENTC_ADD_IDENTITY')])
    conn = FakeSocket(util.frame(msg))
    server.handle_connection(conn, handler, mutex)
    conn.tx.seek(0)
    reply = util.read_frame(conn.tx)
    assert reply == util.pack('B', protocol.msg_code('SSH_AGENT_FAILURE'))

    conn_mock = mock.Mock(spec=FakeSocket)
    conn_mock.recv.side_effect = [Exception, EOFError]
    server.handle_connection(conn=conn_mock, handler=None, mutex=mutex)


def test_server_thread():
    sock = FakeSocket()
    connections = [sock]
    quit_event = threading.Event()

    class FakeServer:
        def accept(self):
            if not connections:
                raise socket.timeout()
            return connections.pop(), 'address'

        def getsockname(self):
            return 'fake_server'

    def handle_conn(conn):
        assert conn is sock
        quit_event.set()

    server.server_thread(sock=FakeServer(),
                         handle_conn=handle_conn,
                         quit_event=quit_event)
    quit_event.wait()


def test_spawn():
    obj = []

    def thread(x):
        obj.append(x)

    with server.spawn(thread, {'x': 1}):
        pass

    assert obj == [1]


def test_run():
    assert server.run_process(['true'], environ={}) == 0
    assert server.run_process(['false'], environ={}) == 1
    assert server.run_process(command=['bash', '-c', 'exit $X'],
                              environ={'X': '42'}) == 42

    with pytest.raises(OSError):
        server.run_process([''], environ={})


def test_remove():
    path = 'foo.bar'

    def remove(p):
        assert p == path

    server.remove_file(path, remove=remove)

    def remove_raise(_):
        raise OSError('boom')

    server.remove_file(path, remove=remove_raise, exists=lambda _: False)

    with pytest.raises(OSError):
        server.remove_file(path, remove=remove_raise, exists=lambda _: True)


def _assuan_connect(path, nonce=None):
    """Connect as libassuan does on Windows: read the port, send the nonce."""
    with open(path, 'rb') as f:
        port, file_nonce = f.read().split(b'\n', 1)
    conn = socket.create_connection(('127.0.0.1', int(port)))
    conn.sendall(file_nonce if nonce is None else nonce)
    return conn


def test_assuan_nonce_socket_server():
    path = tempfile.mktemp()
    with server.assuan_nonce_socket_server(path) as sock:
        with open(path, 'rb') as f:
            port, nonce = f.read().split(b'\n', 1)
        assert int(port) == sock.getsockname()[1]
        assert len(nonce) == server.ASSUAN_NONCE_LEN

        client = _assuan_connect(path)
        conn, _ = sock.accept()
        client.sendall(b'GETINFO version\n')
        assert conn.recv(100) == b'GETINFO version\n'
        conn.close()
        client.close()
    assert not os.path.exists(path)


def test_assuan_nonce_socket_server_drops_a_wrong_nonce():
    path = tempfile.mktemp()
    with server.assuan_nonce_socket_server(path) as sock:
        accepted = []
        thread = threading.Thread(target=lambda: accepted.append(sock.accept()))
        thread.start()
        intruder = _assuan_connect(path, nonce=b'\x00' * server.ASSUAN_NONCE_LEN)
        assert intruder.recv(1) == b''  # dropped, never handed to the agent
        intruder.close()
        client = _assuan_connect(path)  # the next, correct client is served
        thread.join(timeout=10)
        assert len(accepted) == 1
        accepted[0][0].close()
        client.close()


windows_only = pytest.mark.skipif(not sys.platform.startswith('win'),
                                  reason='named pipes are the Windows agent transport')


def _pipe_name():
    return r'\\.\pipe\libagent-test-' + os.urandom(6).hex()


@windows_only
def test_named_pipe_server_serves_a_client():
    name = _pipe_name()
    with server.named_pipe_server(name) as sock:
        assert sock.getsockname() == name
        client = open(name, 'r+b', buffering=0)  # what ssh does: CreateFile on SSH_AUTH_SOCK
        conn, _ = sock.accept()
        client.write(b'\x00\x00\x00\x01\x0b')  # one ssh-agent frame
        assert util.read_frame(conn) == b'\x0b'
        util.send(conn, b'\x00\x00\x00\x01\x0c')
        assert client.read(5) == b'\x00\x00\x00\x01\x0c'
        client.close()
        assert conn.recv(4) == b''  # the client left: the agent's EOF
        conn.close()


@windows_only
def test_named_pipe_server_times_out_without_a_client():
    with server.named_pipe_server(_pipe_name()) as sock:
        sock.settimeout(0.1)
        with pytest.raises(socket.timeout):
            sock.accept()


@windows_only
def test_named_pipe_server_refuses_a_name_already_taken():
    name = _pipe_name()
    with server.named_pipe_server(name):
        with pytest.raises(OSError):
            with server.named_pipe_server(name):
                pass
