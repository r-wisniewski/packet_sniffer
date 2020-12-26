# Usage

```
Usage: sudo ./packet_sniffer

Options:
	-C: color flag. Use to color code output.
```
# Purpose

IP packet sniffer that outputs basic information about captured packets.

# Additional Information

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
