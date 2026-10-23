### Scan vs heap eviction (20000 distinct IPs, seconds)

| capacity k | scan | heap | scan/heap |
|---|---|---|---|
| 10 | 0.030 | 0.016 | 1.9x |
| 100 | 0.123 | 0.017 | 7.3x |
| 1000 | 1.117 | 0.014 | 80.7x |
