"""Live path checks use a controlled subprocess, never a real interface."""

from pathlib import Path
import signal
import sys

import pytest

from ipsec_analyzer.assessment.analyze import analyze_capture
from ipsec_analyzer.ingestion.capture import CaptureError
from ipsec_analyzer.ingestion.live import _stop, capture_window
import ipsec_analyzer.ingestion.live as live_module


FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_ipsec.pcap"


def test_live_window_matches_offline_analysis(tmp_path):
    simulator = tmp_path / "fake_tcpdump.py"
    simulator.write_text(
        "import pathlib, sys\n"
        "pathlib.Path(sys.argv[sys.argv.index('-w') + 1]).write_bytes(pathlib.Path(sys.argv[1]).read_bytes())\n"
        "sys.stderr.write('4 packets captured\\n0 packets dropped by kernel\\n')\n"
    )
    live = capture_window("eth0", 2, _command=[sys.executable, str(simulator), str(FIXTURE)], _check_interface=False)
    assert live["analysis"] == analyze_capture(FIXTURE).to_dict()
    assert live["live_capture"]["packets_dropped_by_kernel"] == 0
    assert live["live_capture"]["raw_capture_retained"] is False
    assert live["live_capture"]["capture_bytes"] == FIXTURE.stat().st_size


def test_no_packets_cleans_temporary_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(live_module.tempfile, "tempdir", str(tmp_path))
    simulator = tmp_path / "empty.py"
    simulator.write_text("import pathlib, sys\npathlib.Path(sys.argv[sys.argv.index('-w') + 1]).write_bytes(b'')\n")
    with pytest.raises(CaptureError, match="No packets captured"):
        capture_window("eth0", 1, _command=[sys.executable, str(simulator)], _check_interface=False)
    assert not list(tmp_path.glob("ipsec-live-*"))


def test_byte_limit_cleans_temporary_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(live_module.tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(live_module, "MAX_BYTES", 32)
    simulator = tmp_path / "large.py"
    simulator.write_text(
        "import pathlib, sys\n"
        "pathlib.Path(sys.argv[sys.argv.index('-w') + 1]).write_bytes(b'x' * 64)\n"
    )
    with pytest.raises(CaptureError, match="byte limit"):
        capture_window("eth0", 1, _command=[sys.executable, str(simulator)], _check_interface=False)
    assert not list(tmp_path.glob("ipsec-live-*"))


def test_process_failure_reports_stderr_and_cleans_temp(tmp_path, monkeypatch):
    monkeypatch.setattr(live_module.tempfile, "tempdir", str(tmp_path))
    simulator = tmp_path / "denied.py"
    simulator.write_text("import sys\nsys.stderr.write('permission denied\\n')\nsys.exit(1)\n")
    with pytest.raises(CaptureError, match="tcpdump failed with exit code 1: permission denied"):
        capture_window("eth0", 1, _command=[sys.executable, str(simulator)], _check_interface=False)
    assert not list(tmp_path.glob("ipsec-live-*"))


def test_packet_cap_passed_to_capture_process(tmp_path):
    simulator = tmp_path / "packet_cap.py"
    simulator.write_text(
        "import pathlib, sys\n"
        "assert sys.argv[sys.argv.index('-c') + 1] == '7'\n"
        "pathlib.Path(sys.argv[sys.argv.index('-w') + 1]).write_bytes(pathlib.Path(sys.argv[1]).read_bytes())\n"
    )
    result = capture_window("eth0", 1, max_packets=7,
                            _command=[sys.executable, str(simulator), str(FIXTURE)], _check_interface=False)
    assert result["live_capture"]["stop_reason"] == "process_exit"


@pytest.mark.parametrize("name", ["any", "eth0;touch /tmp/x", "", "a" * 33])
def test_interface_rejected(name):
    with pytest.raises(CaptureError, match="named network interface"):
        capture_window(name, _check_interface=False)


def test_stop_sends_interrupt_and_waits():
    class Process:
        def __init__(self):
            self.sent = None
            self.waited = False

        def poll(self):
            return None

        def send_signal(self, value):
            self.sent = value

        def terminate(self):
            self.sent = "terminate"

        def wait(self, timeout):
            self.waited = True

    process = Process()
    _stop(process)
    assert process.sent == ("terminate" if sys.platform == "win32" else signal.SIGINT)
    assert process.waited


def test_stop_escalates_when_process_ignores_interrupt_and_terminate():
    class Process:
        def __init__(self):
            self.events = []

        def poll(self):
            return None

        def send_signal(self, value):
            self.events.append(("signal", value))

        def terminate(self):
            self.events.append(("terminate",))

        def kill(self):
            self.events.append(("kill",))

        def wait(self, timeout):
            self.events.append(("wait", timeout))
            if timeout in (3, 2) and ("kill",) not in self.events:
                raise live_module.subprocess.TimeoutExpired("fake", timeout)

    process = Process()
    _stop(process)
    first = ("terminate",) if sys.platform == "win32" else ("signal", signal.SIGINT)
    assert process.events == [first, ("wait", 3), ("terminate",),
                              ("wait", 2), ("kill",), ("wait", 2)]
