#!/usr/bin/env python3
import argparse
import base64
import os
import secrets
import socket
import ssl
import struct
import sys


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise RuntimeError("connection closed")
        data += chunk
    return data


def ws_send_text(sock, text: str):
    payload = text.encode("utf-8")
    fin_opcode = 0x81
    mask_bit = 0x80
    length = len(payload)

    header = bytearray([fin_opcode])
    if length < 126:
        header.append(mask_bit | length)
    elif length <= 0xFFFF:
        header.append(mask_bit | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(mask_bit | 127)
        header.extend(struct.pack("!Q", length))

    mask = secrets.token_bytes(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + mask + masked)


def ws_recv_text(sock) -> str:
    b1, b2 = recv_exact(sock, 2)
    opcode = b1 & 0x0F
    masked = (b2 & 0x80) != 0
    length = b2 & 0x7F

    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]

    mask_key = recv_exact(sock, 4) if masked else None
    payload = recv_exact(sock, length)

    if masked and mask_key:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    if opcode == 0x1:
        return payload.decode("utf-8", errors="replace")
    if opcode == 0x8:
        return "<CLOSE>"
    raise RuntimeError(f"unexpected opcode: {opcode}")


def connect_wss(host: str, port: int, timeout: float):
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("ascii")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw = socket.create_connection((host, port), timeout=timeout)
    sock = ctx.wrap_socket(raw, server_hostname=host)
    sock.settimeout(timeout)
    sock.sendall(req)
    resp = sock.recv(4096)
    if b"101" not in resp.split(b"\r\n", 1)[0]:
        sock.close()
        raise RuntimeError("websocket handshake failed")
    return sock


def main():
    parser = argparse.ArgumentParser(description="Send afirma:// URI to local WSS AutoFirma-compatible server")
    parser.add_argument("uri", help="Full afirma:// URI")
    parser.add_argument("--host", default=os.getenv("AUTOFIRMA_WS_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("AUTOFIRMA_WS_PORT", "63117")))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("AUTOFIRMA_WS_TIMEOUT", "20")))
    args = parser.parse_args()

    if not args.uri.startswith("afirma://"):
      print("ERROR: uri must start with afirma://", file=sys.stderr)
      sys.exit(2)

    sock = connect_wss(args.host, args.port, args.timeout)
    try:
        ws_send_text(sock, args.uri)
        response = ws_recv_text(sock)
        print(response)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
