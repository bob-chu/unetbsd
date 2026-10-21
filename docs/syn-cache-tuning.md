# SYN-cache hash table tuning

Apply the NetBSD source patch after cloning `netbsd_src`:

```bash
git -C netbsd_src apply ../syn-cache-size.patch
```

Set the optional top-level `tcp_syn_cache_size` field in a `perf_tool` JSON
configuration to choose the number of SYN-cache hash buckets:

```json
{
  "tcp_syn_cache_size": 4099
}
```

Add this field to a complete client or server configuration. The default is 293;
accepted values are integers from 1 through 1048576. Each process uses its own
setting. The table is allocated during stack initialization and cannot be resized
while running. This setting does not change the total entry limit
(`tcp_syn_cache_limit`) or per-bucket entry limit (`tcp_syn_bucket_limit`).

Applications using the stack directly can call
`sysctl_tun("tcp_syn_cache_size", 4099)` **before** `netbsd_init()`.
Invalid values and attempts to change the size after initialization are rejected
with a diagnostic, leaving the existing size unchanged.
