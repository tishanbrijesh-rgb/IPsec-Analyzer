"""Bounded, explicit Linux interface capture followed by the offline analyzer."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ipsec_analyzer.assessment.analyze import analyze_capture
from ipsec_analyzer.ingestion.capture import CaptureError

MAX_SECONDS = 60
MAX_PACKETS = 10_000
MAX_BYTES = 16 * 1024 * 1024
FILTER = "udp port 500 or udp port 4500 or ip proto 50 or ip proto 51 or ip6 proto 50 or ip6 proto 51"
INTERFACE_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,32}\Z")
DROP_COUNT = re.compile(r"(?m)^\s*(\d+) packets dropped by kernel\s*$")


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if sys.platform == "win32":
        # Windows subprocesses do not receive POSIX SIGINT reliably unless
        # launched as a console process group. The live CLI itself is Linux-only.
        process.terminate()
    else:
        process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def capture_window(
    interface: str,
    seconds: int = 10,
    max_packets: int = MAX_PACKETS,
    *,
    _command: list[str] | None = None,
    _check_interface: bool = True,
) -> dict:
    """Capture once, analyze the temporary PCAP, and remove it on return."""
    if not INTERFACE_NAME.fullmatch(interface) or interface == "any":
        raise CaptureError("Choose one named network interface")
    if not 1 <= seconds <= MAX_SECONDS or not 1 <= max_packets <= MAX_PACKETS:
        raise CaptureError("Capture limits are outside the supported range")
    if _check_interface:
        if not sys.platform.startswith("linux"):
            raise CaptureError("Live capture requires Linux or WSL")
        try:
            socket.if_nametoindex(interface)
        except OSError as exc:
            raise CaptureError(f"Network interface is unavailable: {interface}") from exc
    command = _command if _command is not None else ([shutil.which("tcpdump")] if shutil.which("tcpdump") else None)
    if not command:
        raise CaptureError("tcpdump is required for live capture")
    with tempfile.TemporaryDirectory(prefix="ipsec-live-") as directory:
        capture_path = Path(directory) / "window.pcap"
        stderr_path = Path(directory) / "tcpdump.stderr"
        args = [*command, "-i", interface, "-s", "0", "-U", "-w", str(capture_path), "-c", str(max_packets), FILTER]
        started = time.monotonic()
        with stderr_path.open("wb") as stderr_file:
            try:
                process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr_file)
            except OSError as exc:
                raise CaptureError(f"Could not start tcpdump: {exc}") from exc
            stop_reason = "process_exit"
            try:
                while process.poll() is None:
                    if capture_path.exists() and capture_path.stat().st_size > MAX_BYTES:
                        stop_reason = "byte_limit"
                        break
                    if time.monotonic() - started >= seconds:
                        stop_reason = "duration"
                        break
                    time.sleep(0.05)
            finally:
                _stop(process)
        elapsed = time.monotonic() - started
        stderr = stderr_path.read_bytes()[-16_384:].decode("utf-8", errors="replace")
        drop_match = DROP_COUNT.search(stderr)
        dropped = int(drop_match.group(1)) if drop_match else None
        if stop_reason == "byte_limit" or (capture_path.exists() and capture_path.stat().st_size > MAX_BYTES):
            raise CaptureError("Live capture exceeded its byte limit")
        if process.returncode not in (0, -signal.SIGINT):
            raise CaptureError(f"tcpdump failed with exit code {process.returncode}: {stderr.strip()[-500:]}")
        if not capture_path.is_file() or capture_path.stat().st_size <= 24:
            raise CaptureError(f"No packets captured; tcpdump exit code {process.returncode}: {stderr.strip()[-500:]}")
        capture_bytes = capture_path.stat().st_size
        analysis_started = time.monotonic()
        result = analyze_capture(capture_path).to_dict()
        return {
            "live_capture": {
                "interface": interface,
                "requested_seconds": seconds,
                "elapsed_seconds": round(elapsed, 3),
                "stop_reason": stop_reason,
                "packets_dropped_by_kernel": dropped,
                "capture_bytes": capture_bytes,
                "analysis_seconds": round(time.monotonic() - analysis_started, 3),
                "raw_capture_retained": False,
            },
            "analysis": result,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture one bounded IPsec window on Linux/WSL and analyze it")
    parser.add_argument("--interface", required=True, help="Explicit network interface name (not 'any')")
    parser.add_argument("--seconds", type=int, default=10, help="Window length, 1–60 seconds")
    parser.add_argument("--max-packets", type=int, default=MAX_PACKETS, help="Packet cap, 1–10000")
    args = parser.parse_args(argv)
    try:
        result = capture_window(args.interface, args.seconds, args.max_packets)
    except CaptureError as exc:
        print(f"Live capture error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
