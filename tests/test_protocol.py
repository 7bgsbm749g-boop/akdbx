import socket
import struct
import unittest

from akdbx.protocol import MAX_MESSAGE, ProtocolError, receive_message, send_message


def test_rejects_oversized_message_before_reading_body():
    left, right = socket.socketpair()
    left.sendall(struct.pack("!I", MAX_MESSAGE + 1))
    with unittest.TestCase().assertRaisesRegex(ProtocolError, "too large"):
        receive_message(right)
    left.close()
    right.close()


def test_send_boundary_excludes_oversized_messages_and_precedes_delivery():
    left, right = socket.socketpair()
    sent = []
    try:
        with unittest.TestCase().assertRaisesRegex(ProtocolError, 'too large'):
            send_message(left, {'value': 'x' * MAX_MESSAGE}, before_send=lambda: sent.append(True))
        assert not sent
        send_message(left, {'action': 'ping'}, before_send=lambda: sent.append(True))
        assert sent == [True] and receive_message(right) == {'action': 'ping'}
    finally:
        left.close()
        right.close()


def test_send_boundary_marks_transport_failure_as_possibly_sent():
    left, right = socket.socketpair()
    right.close()
    sent = []
    try:
        with unittest.TestCase().assertRaises(OSError):
            send_message(left, {'action': 'fill'}, before_send=lambda: sent.append(True))
        assert sent == [True]
    finally:
        left.close()
