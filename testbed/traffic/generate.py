"""Bounded synthetic traffic profiles for an isolated IPsec lab.

Labels describe this generator's behavior, not decoded applications.
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import struct
import subprocess
import time
from pathlib import Path

PROFILES = {
    "voip-like": {"transport": "udp", "port": 18101, "size": 160, "count": 40, "interval_s": 0.02},
    "video-like": {"transport": "udp", "port": 18102, "size": 1100, "count": 40, "interval_s": 0.03},
    "messaging-like": {"transport": "tcp", "port": 18103, "size": 48, "count": 12, "interval_s": 0.10},
    "email-like": {"transport": "tcp", "port": 18104, "size": 512, "count": 16, "interval_s": 0.06},
    "web-like": {"transport": "tcp", "port": 18105, "size": 1024, "count": 20, "interval_s": 0.02},
    "icmp": {"transport": "icmp", "port": None, "size": 56, "count": 3, "interval_s": 1.0},
}
MAX_FRAME = 2048


def pattern(profile_name: str, seed: int) -> tuple[list[int], list[float]]:
    """Derive the same bounded run pattern at both ends of a connection."""
    if not 0 <= seed <= 1000000:
        raise ValueError("seed must be between 0 and 1000000")
    profile = PROFILES[profile_name]
    if seed == 0:
        return [profile["size"]] * profile["count"], [profile["interval_s"]] * profile["count"]
    rng = random.Random(f"sih4:{profile_name}:{seed}")
    sizes = [max(16, min(MAX_FRAME, profile["size"] + rng.randint(-profile["size"] // 5, profile["size"] // 5)))
             for _ in range(profile["count"])]
    intervals = [max(0.005, profile["interval_s"] * rng.uniform(0.75, 1.25))
                 for _ in range(profile["count"])]
    return sizes, intervals


def _read_exact(stream: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Synthetic traffic stream ended early")
        data.extend(chunk)
    return bytes(data)


def serve(profile_name: str, bind: str, seed: int = 0) -> dict[str, object]:
    profile = PROFILES[profile_name]
    if profile["transport"] == "icmp":
        raise ValueError("ICMP does not require a server")
    count = profile["count"]
    sizes, _ = pattern(profile_name, seed)
    received = 0
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM if profile["transport"] == "udp" else socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind, profile["port"]))
        server.settimeout(15)
        if profile["transport"] == "udp":
            for expected_size in sizes:
                payload, address = server.recvfrom(MAX_FRAME)
                if len(payload) != expected_size:
                    raise ValueError("Unexpected synthetic UDP size")
                received += len(payload)
                server.sendto(b"ack", address)
        else:
            server.listen(1)
            stream, _ = server.accept()
            with stream:
                stream.settimeout(15)
                for expected_size in sizes:
                    length = struct.unpack("!I", _read_exact(stream, 4))[0]
                    if length != expected_size or length > MAX_FRAME:
                        raise ValueError("Unexpected synthetic TCP frame size")
                    received += len(_read_exact(stream, length))
                    stream.sendall(b"ack")
    return {"profile": profile_name, "role": "receiver", "messages": count, "payload_bytes": received}


def send(profile_name: str, target: str, source: str | None = None, seed: int = 0) -> dict[str, object]:
    profile = PROFILES[profile_name]
    sizes, intervals = pattern(profile_name, seed)
    if profile["transport"] == "icmp":
        command = ["ping", "-c", str(profile["count"]), "-W", "2"]
        if source:
            command.extend(["-I", source])
        subprocess.run(command + [target], check=True, capture_output=True, text=True, timeout=15)
        return {"profile": profile_name, "role": "sender", "messages": profile["count"],
                "payload_bytes": None, "label_source": "synthetic generator command", "seed": seed}
    payload_bytes = 0
    kind = socket.SOCK_DGRAM if profile["transport"] == "udp" else socket.SOCK_STREAM
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    with socket.socket(family, kind) as client:
        client.settimeout(15)
        if source:
            client.bind((source, 0))
        client.connect((target, profile["port"]))
        for index in range(profile["count"]):
            payload = bytes([index % 251]) * sizes[index]
            if kind == socket.SOCK_DGRAM:
                client.send(payload)
                if client.recv(MAX_FRAME) != b"ack":
                    raise ValueError("Unexpected synthetic UDP acknowledgement")
            else:
                client.sendall(struct.pack("!I", len(payload)) + payload)
                if _read_exact(client, 3) != b"ack":
                    raise ValueError("Unexpected synthetic TCP acknowledgement")
            payload_bytes += len(payload)
            if index + 1 < profile["count"]:
                time.sleep(intervals[index])
    return {"profile": profile_name, "role": "sender", "messages": profile["count"],
            "payload_bytes": payload_bytes, "label_source": "synthetic generator command", "seed": seed}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("send", "serve"))
    parser.add_argument("profile", choices=sorted(PROFILES))
    parser.add_argument("--address", required=True, help="target for send, bind address for serve")
    parser.add_argument("--source", help="sender source address")
    parser.add_argument("--record", type=Path, help="write secret-free generator record")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    result = send(args.profile, args.address, args.source, args.seed) if args.role == "send" else serve(args.profile, args.address, args.seed)
    if args.record:
        if args.record.exists():
            raise ValueError("Generator record already exists")
        args.record.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
