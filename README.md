# HomeSniff

HomeSniff is an open-source tool designed for forensic analysis in networks operated by the IEEE 802.15.4 standard. It is implemented as a custom integration to the Home Assistant Operating System, making it compatible with low-cost general-purpose hardware like Raspberry Pi. HomeSniff simplifies the setup and automation of IoT forensic data collection by providing ready-to-use functionalities for capturing network traffic and extracting its characteristics.

## Features

- **Packet capture**: HomeSniff allows TCPdump-like traffic capture over the 802.15.4 physical layer, saving raw packet data in the PCAP file format. It supports traditional packet filters for processing a subset of sniffed packets based on criteria like source/destination addresses, packet type, PAN address, etc.

- **Time-windowed feature extraction**: For IoT forensic analysis, statistical features extracted from network traffic are crucial. HomeSniff enables easy extraction of network features in a time-windowed fashion from 802.15.4 traffic. It organizes received traffic into user-defined time windows and computes a set of traffic features for each device based on its source address in the MAC header. The extracted features, including packet size, payload length, and inter-arrival time, are saved in a CSV file for further analysis.

- **Offline traffic analysis**: HomeSniff supports feature extraction from existing PCAP files containing 802.15.4 raw packets, allowing offline traffic analysis.

## Compatibility

HomeSniff is compatible with various devices, including Crossbow Telosb Motes, Texas Instruments CC2530/1, and Silicon Labs EFR32 family SoC. It utilizes a dedicated radio interface compatible with the Killerbee Software suite for traffic capture.

For detailed information and usage instructions, refer to the [HomeSniff GitHub repository](https://github.com/antonio-boiano/HomeSniff/tree/main).

# Installation
To install the component, clone the repo under custom_components in Home Assistant main configuration folder. Add the followinf lines ad the end of the Configuration.yaml file present into the Home Assistant main configuration folder.
```python
forensics_15_4:
  zb_channel: 15 # [REQUIRED] IEEE 802.15.4 channel to sniff
  device: '/dev/ttyUSB0' # [OPTIONAL] Path to the sniffer peripheral
  device_class: 'telosb' # [OPTIONAL] Type of device

```
