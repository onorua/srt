# Reed-Solomon FEC Filter

The `rsfec` packet filter implements forward error correction based on the Reed-Solomon algorithm. It is compiled with the library and can be enabled with the `packetfilter` URI parameter or by setting the `SRTO_PACKETFILTER` socket option.

## Configuration

Specify the number of data packets `k` and parity packets `parity` that form one FEC block. For example:

```
srt://receiver:5000?latency=500&packetfilter=rsfec,k:10,parity:2
```

Both peers must use the same configuration. The receiver only needs to specify the filter type (for example `packetfilter=rsfec`) if the sender provides the full set of parameters.

The latency must be large enough to cover the time required to transmit all packets of a block. See [SRT Packet Filtering & FEC](packet-filtering-and-fec.md) for details about computing the required latency.

## Additional parameters

`timeout` sets a timeout in milliseconds for completing a block. If fewer than `k` packets arrive within this time, the partial block is flushed without parity. Default is `0` (disabled).
