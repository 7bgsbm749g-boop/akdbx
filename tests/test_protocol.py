import socket
import struct
import unittest

from agentic_kdbx.protocol import MAX_MESSAGE, ProtocolError, receive_message


def test_rejects_oversized_message_before_reading_body():
    left, right = socket.socketpair()
    left.sendall(struct.pack("!I", MAX_MESSAGE + 1))
    with unittest.TestCase().assertRaisesRegex(ProtocolError, "too large"):
        receive_message(right)
    left.close()
    right.close()
