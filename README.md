# Security Monitoring Tool to detect DDoS attacks
## Spring 2020
This is a simple Python-based tool to detect Distributed Denial of Service (DDoS) attacks from a PCAP file.

The tool will parse a PCAP file to provide details of the traffic captured. PCAP files are generated
by using programs that capture network packet data from a live network, i.e. Wireshark, and can
be used to analyze the characteristics of certain data. A demo PCAP file is included above. 

If the script detects any DDoS attack, it prints the victim’s IP address. Additionally, it also prints other information regarding the attack for instance, the number of packets, the Geo-location of some IP addresses involved, and other statistical data. The count for each IP Address is calculated to determine which IPs are making numerous connection and is represented in Table and graph format.The Geo-location of each IP address is checked to decide duplicate or malicious IP addresses. Finally, script also checks for TCP SYN flood attack, which is one of the common types of DDoS attack.

## Usage:
```
Clone the DDoS_Detection_Tool Repository:
$ git clone https://github.com/Ab-spyder/DDoS_Detection_Tool.git

Go to the DDoS_Detection_Tool directory.
$ cd DDoS_Detection_Tool

Run the DDoS Detection tool.
$ python3 DDOS_tool.py --pcap <pcap file name>

```
