# pcapy-ng examples

Self-contained, runnable scripts. Each takes either a network device (live capture, needs
privileges) or a `.pcap` file (no privileges) as its first argument.

```sh
python 02_read_pcap.py capture.pcap          # offline, no root
sudo python 03_filter_in_c.py eth0           # live, needs root / CAP_NET_RAW
```

| Script | What it shows |
|--------|---------------|
| `01_sniff_live.py` | Classic capture: `open_live` + BPF filter + `next()`. |
| `02_read_pcap.py` | Read a saved capture with `open_offline` and summarize it. |
| `03_filter_in_c.py` | `loop_filtered`: tag + count packets, drop `OTHER` in C. |
| `04_flow_heads.py` | Grab the first packets of each connection (`flow_cutoff`) — e.g. the TLS server name. |
| `05_shared_memory_ring.py` | `loop_to_buffer` producer + multiprocess consumers (Python 3). |
| `06_live_stats.py` | Poll `filtered_stats()` from another thread during capture. |

Don't have a capture handy? Make one (any traffic will do):

```sh
sudo tcpdump -i any -s 2000 -w capture.pcap   # Ctrl-C after a bit
python 03_filter_in_c.py capture.pcap
```
