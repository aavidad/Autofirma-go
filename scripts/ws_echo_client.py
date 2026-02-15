#!/usr/bin/env python3
import base64
import os
import secrets
import socket
import ssl
import struct
import sys

HOST = os.getenv("AUTOFIRMA_WS_HOST", "127.0.0.1")
PORT = int(os.getenv("AUTOFIRMA_WS_PORT", "63117"))
RESOURCE = "/"
MSG = os.getenv("AUTOFIRMA_WS_ECHO", "echo=test@EOF")
TIMEOUT = float(os.getenv("AUTOFIRMA_WS_TIMEOUT", "5"))


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
    raise RuntimeError(f"unexpected opcode: {opcode}")


def main():
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        f"GET {RESOURCE} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("ascii")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=HOST) as sock:
            sock.settimeout(TIMEOUT)
            sock.sendall(req)
            resp = sock.recv(4096)
            if b"101" not in resp.split(b"\r\n", 1)[0]:
                print("HANDSHAKE_FAIL")
                print(resp.decode("utf-8", errors="replace"))
                sys.exit(2)

            ws_send_text(sock, MSG)
            text = ws_recv_text(sock)
            print(text)

            if text == "OK":
                sys.exit(0)
            sys.exit(1)


if __name__ == "__main__":
    main()
