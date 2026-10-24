### Memory (KiB) and time (s) as distinct IPs grow (each IP seen once)

| distinct IPs | Exact KiB | Exact s | CMS KiB | CMS s | SS KiB | SS s |
|---|---|---|---|---|---|---|
| 1000 | 25.8 | 0.00 | 2.7 | 0.02 | 1.3 | 0.00 |
| 10000 | 203.0 | 0.01 | 2.7 | 0.21 | 1.9 | 0.04 |
| 100000 | 3755.0 | 0.08 | 12.1 | 2.05 | 1.9 | 0.45 |
| 500000 | 15019.0 | 0.52 | 12.1 | 9.62 | 1.9 | 2.47 |

### Live simulation: memory (KiB) after N batches of 5-10 events (CMS 100x3, SS k=10)

| batches | events | distinct IPs | Exact KiB | CMS KiB | SS KiB |
|---|---|---|---|---|---|
| 10 | 68 | 23 | 1.2 | 2.9 | 1.4 |
| 100 | 744 | 236 | 7.0 | 3.0 | 1.8 |
| 1000 | 7463 | 2347 | 51.4 | 3.5 | 2.5 |
| 10000 | 74916 | 23297 | 939.5 | 12.9 | 3.1 |

Reading the tables: the exact counter gains one entry per new distinct IP, so its memory keeps growing for as long as the monitor runs. CMS and Space-Saving keep a fixed number of counters/slots; their small KiB increase is Python allocating larger int objects once counts exceed 256, not extra entries. The price of the fixed memory is accuracy (CMS can over-estimate) and speed (CMS does d md5 hashes per update).
