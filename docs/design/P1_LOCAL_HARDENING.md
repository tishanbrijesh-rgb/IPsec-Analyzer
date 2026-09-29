# P1 local processing and result lifecycle

**Verified 29 September 2026.** This is the local, single-user prototype
boundary. The API binds to loopback and has no user authentication. It must
not be exposed as a network service.

## Capture limits and cleanup

- The API accepts at most 16 MiB of PCAP/PCAPNG bytes per upload. It streams
  those bytes into a temporary directory, runs synchronous analysis, then
  removes the raw upload on success or an invalid-capture error. The offline
  reader has its own 128 MiB file cap and 250,000-packet cap for CLI use.
- The Linux/WSL live command accepts one named interface, at most 60 seconds,
  10,000 packets and 16 MiB of temporary capture bytes. It asks tcpdump to
  stop at the packet count, checks file size while capturing, and stops the
  child at the duration/byte limit. Stop escalates from SIGINT to terminate
  and then kill if the child ignores deadlines. The temporary directory is
  removed after analysis or failure.
- A tcpdump failure now reports its exit code and bounded stderr before a
  missing capture is described as a no-packet window. Simulated tests cover
  no packets, permission-style failure, byte limit, packet-cap argument,
  live/offline parity and stop escalation. One real controlled WSL namespace
  run has since verified host permissions, zero kernel drops and cleanup; see
  [phase status](IMPLEMENTATION_STATUS.md). Repeated load checks remain open.

The byte cap is checked at polling intervals, so tcpdump can briefly write
beyond 16 MiB before it is stopped. The command then rejects and removes that
capture; 16 MiB is an accepted-result limit, not an instantaneous disk-write
limit. OS disk and process quotas are not enforced by this Python prototype.

## Local API result lifecycle

Each successful upload receives a random analysis ID and is immediately
`complete`. At most 16 results remain in process memory. A seventeenth
successful upload evicts the oldest result; its analysis, status and report
URLs then return 404. All results disappear on server restart. There is no
time-based expiry, durable job queue, multi-user isolation or persistent
report store. Tests exercise eviction and restart semantics with a reduced
cap, as well as raw-upload cleanup after invalid input.
  The actual 16 MiB plus one byte boundary is also tested: the API returns
  413 and leaves no temporary capture.

Durable jobs are deferred until a required result lifetime and concurrency
target are specified. For the current guided local demo, re-uploading a
capture after restart is the documented recovery path.

## Reproducible offline baseline

From the repository root in PowerShell:

```powershell
$env:PYTHONPATH='src'
python tests/benchmark_offline.py data/sample/modern-tunnel.pcap data/sample/phase4-video-05.pcap --repeats 5
python tests/benchmark_offline.py --synthetic-packets 10000 --repeats 5
```

The 29 September 2026 run used Windows 11 build 26200, Python 3.14.7,
`Intel64 Family 6 Model 183 Stepping 1, GenuineIntel`, 20 logical CPUs.

| Controlled capture | Bytes | Packets | Median wall time, five runs | Maximum Python allocation peak |
| --- | ---: | ---: | ---: | ---: |
| `modern-tunnel.pcap` | 2,407 | 10 | 0.00514 s | 186,582 bytes |
| `phase4-video-05.pcap` | 57,264 | 84 | 0.01284 s | 294,387 bytes |
| Temporary repeated ESP fixture | 1,700,024 | 10,000 | 1.97929 s | 10,629,038 bytes |

The synthetic fixture repeats one controlled ESP frame with increasing
timestamps. It probes the live packet-count ceiling but has only one simple
flow and is not representative of mixed real traffic. The benchmark includes
`tracemalloc` overhead. Its peak is tracked Python allocations, not total
resident memory. These runs cannot establish throughput at the API upload
byte limit or on a real interface. Repeat on the intended demo host with
representative capture sizes before making a capacity claim.

## P1 gate status

| Workstream | Status |
| --- | --- |
| Local capture and API resource hardening | Verified within the documented prototype bounds; one controlled real-interface smoke run passed; representative live-load measurements remain open |
| API durability | Defined as in-memory, 16-result, restart-volatile for the local demo; durable storage is not required for this delivery mode |
| Independent-host dataset/model validation | Open: no second host is available, so the classifier remains a one-host synthetic pilot |
