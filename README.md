# Usage

```
Usage: sudo ./packet_sniffer [-C] [-P]

Options:
	-C: color flag. Use to color code output.
	-P: Put interface into promiscuous mode.
```
# Purpose

IP packet sniffer that outputs basic information about captured packets.

If the interface that should be put into promiscuous mode is not interface 2, replace the line
```
mreq.mr_ifindex = 2;
```
with the appropriate interface that should be put into promiscuous mode and recompile the program.

# Promiscuous mode

Depending on your networking configuration, you maybe able to sniff packets destined for other devices by turning on [Promiscuous mode](https://en.wikipedia.org/wiki/Promiscuous_mode). 

To see if it’s already enabled run:
```
ip a show [interface] | grep -i "promisc"
```
If nothing is returned, promiscuous mode is disabled. To enable promiscuous mode run:
```
ip link set [interface] promisc on
```

Note: Running this command will not turn on promiscuous mode permanently. To turn it on permanently, modify the appropriate configuration file for your particular OS.

# Contact

Robin Wisniewski – [LinkedIn](https://www.linkedin.com/in/robin-wisniewski/) –  [wisniewski.ro@gmail.com](mailto:wisniewski.ro@gmail.com)
