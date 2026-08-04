"""Minimal synthetic guacd RDP handshake probe; never use production credentials."""

from __future__ import annotations

import argparse
import socket
import time


def instruction(opcode: str, *values: str) -> bytes:
    parts = (opcode, *values)
    return (",".join(f"{len(value.encode())}.{value}" for value in parts) + ";").encode()


def receive_instruction(connection: socket.socket, buffer: bytearray) -> tuple[list[str], bytearray]:
    values: list[str] = []
    while True:
        while b"." not in buffer:
            chunk = connection.recv(4096)
            if not chunk:
                raise ConnectionError("guacd closed the connection")
            buffer.extend(chunk)
        length_text, remainder = bytes(buffer).split(b".", 1)
        if not length_text.isdigit():
            raise ValueError("invalid Guacamole element length")
        length = int(length_text)
        while len(remainder) < length + 1:
            chunk = connection.recv(4096)
            if not chunk:
                raise ConnectionError("guacd closed the connection")
            remainder += chunk
        values.append(remainder[:length].decode("utf-8", errors="replace"))
        delimiter = remainder[length:length + 1]
        buffer = bytearray(remainder[length + 1:])
        if delimiter == b";":
            return values, buffer
        if delimiter != b",":
            raise ValueError("invalid Guacamole instruction delimiter")


def probe(guacd_host: str, target: str, pin: str, security: str) -> tuple[str, list[str]]:
    safe_events: list[str] = []
    with socket.create_connection((guacd_host, 4822), timeout=5) as connection:
        connection.settimeout(1)
        buffer = bytearray()
        connection.sendall(instruction("select", "rdp"))
        args, buffer = receive_instruction(connection, buffer)
        if not args or args[0] != "args":
            raise RuntimeError("guacd did not return RDP arguments")
        names = args[1:]
        values = {name: "" for name in names}
        values.update({
            "hostname": target,
            "port": "3389",
            "username": "synthetic-user",
            "password": "clearly-fake-password",
            "security": security,
            "ignore-cert": "false",
            "cert-tofu": "false",
            "cert-fingerprints": pin,
        })
        connection.sendall(instruction("size", "1024", "768", "96"))
        connection.sendall(instruction("audio"))
        connection.sendall(instruction("video"))
        connection.sendall(instruction("image", "image/png", "image/jpeg"))
        connection.sendall(instruction("connect", *(values[name] for name in names)))
        deadline = time.monotonic() + 10
        ready_at: float | None = None
        while time.monotonic() < deadline:
            try:
                response, buffer = receive_instruction(connection, buffer)
            except TimeoutError:
                if ready_at is not None and time.monotonic() - ready_at >= 5:
                    return "accepted", safe_events
                continue
            opcode = response[0] if response else ""
            if opcode in {"ready", "error", "disconnect"}:
                safe_events.append(opcode)
            if opcode == "ready":
                ready_at = time.monotonic()
            if opcode in {"error", "disconnect"}:
                return "rejected", safe_events
        return ("accepted" if ready_at is not None else "timeout"), safe_events


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--guacd", default="guacd-review")
    parser.add_argument("--target", required=True)
    parser.add_argument("--pin", default="")
    parser.add_argument("--security", choices=("nla", "tls"), default="nla")
    args = parser.parse_args()
    result, events = probe(args.guacd, args.target, args.pin, args.security)
    print(f"result={result} events={','.join(events) or 'none'}")
    return 0 if result == "accepted" else 2


if __name__ == "__main__":
    raise SystemExit(main())
