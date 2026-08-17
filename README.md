# Network Packet Sniffer & Traffic Analyzer

## Objective

I built this project after learning networking basics through Cisco Networking Academy. I understood the basic concepts of TCP/IP, protocols, and network traffic from the course, but I wanted to actually work with network traffic myself and see how those concepts work in real world. So I set up my Ubuntu Server as a small lab and started building a packet sniffer using Python and Scapy.


The idea is pretty simple; use Python and Scapy to capture live network traffic on my Ubuntu Server and look at what is actually happening at the packet level. Right now, the project focuses on identifying things like source IP, destination IP, and whether the traffic is TCP or UDP.

## How It Works

The script uses Scapy to capture packets from a network interface.

For each packet, it:

* Checks whether the packet has an IP layer.
* Gets the source and destination IP addresses.
* Checks the protocol.
* Prints the packet information so I can see the traffic as it happens.

The script is currently set up to listen on the `tailscale0` interface.

## Why Tailscale / `tailscale0`?

This part came from troubleshooting.

When I first tested the sniffer, I was seeing mostly UDP traffic even when I was connecting to the server through SSH. At first, I thought something was wrong with the packet capture itself.

I checked the network interfaces and realized that my SSH connection was coming through Tailscale. The traffic was using the `tailscale0` interface, while Scapy wasn't specifically listening on that interface.

So I changed the capture code to:

```python
sniff(prn=process_packet, timeout=30, iface="tailscale0")
```

That helped me understand something I hadn't really thought about before, a packet sniffer doesn't automatically see every packet on a network. It sees traffic that is available through the interface it's listening to.

## Tools Used

* Python 3
* [Scapy](https://scapy.net/)
* Tailscale
* Ubuntu Server

## Setup & Usage

Clone the repository and create a virtual environment:

```bash
git clone [github.com/prashantkarn021/packet-sniffer-traffic-analyzer]
cd packet_sniffer

python3 -m venv venv
source venv/bin/activate
```

Install the required packages:

```bash
pip install -r requirements.txt
```

Run the sniffer:

```bash
sudo ./venv/bin/python scripts/sniffer.py
```

Packet capture may require root privileges, which is why `sudo` is used when running the script.

## Current Status

This is an early version of the project. I'm building it step by step.

Right now, the sniffer can capture and display traffic with information such as:

* Source IP
* Destination IP
* Protocol
* TCP/UDP traffic

The basic packet capture is working, but the project doesn't have automated detection or alerting yet.

## Known Limitations

At the moment, the script is mainly showing me what traffic is being captured. It isn't deciding whether that traffic is suspicious.

For example, port-scan detection is something I want to add, but it isn't implemented yet. The idea is to track which ports a source IP is connecting to over a short period of time and look for behavior that could indicate a scan.

## Next Steps

The next part of the project will focus more on actually analyzing the traffic instead of just displaying it.

Some of the things I plan to work on are:

* Detect possible port scans by tracking different destination ports from the same source IP.
* Add a time window for the detection logic.
* Generate an alert when a source IP hits a large number of ports in a short period of time.
* Add ICMP traffic support.
* Improve the output so suspicious activity is easier to notice.

This project is still a work in progress. I'm using it to build my understanding of Python, networking, Linux, and some basic security monitoring by actually working with traffic on a real lab server.
