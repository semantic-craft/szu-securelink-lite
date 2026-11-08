#!/usr/bin/env python3
"""Query the installed privileged status helper over its launchd socket.

Read-only: one fixed five-byte request, one JSON response. No other operation
exists in this protocol version.
"""
import argparse
import json
import socket
import struct
import sys

DEFAULT_SOCKET = "/var/run/local.szu.securelink.helper"
REQUEST = struct.pack(">IB", 1, 0x01)
MAX_RESPONSE = 4096
REQUIRED_KEYS = {"schemaVersion", "helper", "services", "epoch"}


def read_exact(connection: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = connection.recv(remaining)
        if not chunk:
            raise OSError("helper closed the connection early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def query(path: str = DEFAULT_SOCKET, timeout: float = 5.0) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(path)
        connection.sendall(REQUEST)
        header = read_exact(connection, 4)
        (length,) = struct.unpack(">I", header)
        if not 1 <= length <= MAX_RESPONSE:
            raise ValueError(f"unacceptable response length {length}")
        body = read_exact(connection, length)
    value = json.loads(body.decode("utf-8"))
    if not isinstance(value, dict) or not REQUIRED_KEYS.issubset(value):
        raise ValueError("response does not carry the expected schema")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", default=DEFAULT_SOCKET)
    args = parser.parse_args()
    try:
        report = query(args.path)
    except (OSError, ValueError) as error:
        print(f"helper-status: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
