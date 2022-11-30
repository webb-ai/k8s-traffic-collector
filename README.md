# Worker

The distributed network sniffer and kernel tracer. Uses `libpcap`, `AF_PACKET` and eBPF. It's the backbone of Kubeshark.

## Go build

Build:

```shell
go build -o worker .
```

Run:

```shell
sudo ./worker --hub-ws-address ws://localhost:8898/wsWorker -i any
```

> `-i` is the network interface that you want to sniff. `any` is only available on Linux. See `ifconfig -a`
