# SYN FLOOD Detection and Email Alert System

This C++ project captures network packets using the `libpcap` library, detects potential SYN flood attacks, and sends an email alert using `libcurl` when a SYN flood is detected. The program logs packet information into a file and monitors SYN requests, sending an alert if the number of SYN packets from a particular source IP exceeds a predefined threshold within a specified time window.

## Features
- **Packet Capture**: Uses `libpcap` to capture live network packets on a specified interface.
- **SYN Flood Detection**: Detects potential SYN floods by tracking SYN packets from source IPs.
- **Email Alerts**: Sends an email notification when a SYN flood is detected using `libcurl`.
- **Logging**: Logs packet details, including IP addresses, ports, and timestamps, to a file.

## Requirements

### Libraries:
- **libpcap**: For capturing and analyzing network packets.
- **libcurl**: For sending email notifications via SMTP.

To install these libraries:
- On Ubuntu/Debian:
  ```bash
  sudo apt-get install libpcap-dev libcurl4-openssl-dev

## Environment Variables:
Set the following environment variables before running the program:

- **EMAIL_PASSWORD**: Your email app password (e.g., for Gmail, use an app password).
- **SENDER_EMAIL**: The email address from which alerts will be sent.
- **RECEIVER_EMAIL**: The email address that will receive alerts.
- **PACKETS_FILE_PATH**: Path to the file where packet logs will be saved (optional, defaults to packets_file.txt).

## How It Works:
- **Packet Capture**: The program captures TCP packets using libpcap.
- **SYN Flood Detection**: For each TCP packet, it checks if it is a SYN packet. If a source IP sends more than 20 SYN packets within 60 seconds, a potential SYN flood is detected.
- **Email Alert**: When a SYN flood is detected, the program sends an email to the specified recipient with details about the attack.
- **Logging**: All captured packets are logged to a file, including timestamps, IP addresses, ports, and the number of detected SYN packets.

## Code Overview
- **packet_handler()**: Callback function that processes each captured packet. It checks if the packet is a TCP packet and logs the information. If it detects SYN packets, it passes the data to handle_tcp_packet().
- **handle_tcp_packet()**: Tracks the number of SYN packets from each source IP and detects if a SYN flood is occurring. If a flood is detected, it sends an alert email and resets the count for the source IP.
- **send_email_alert()**: Uses libcurl to send an email when a SYN flood is detected. The email contains details about the source IP, SYN count, source, and destination ports.

- **Main Function:**
  - Opens the network interface for packet capture using pcap_open_live().
  - Sets up a filter to capture only IP packets.
  - Starts the packet capture loop using pcap_loop().

## Constants
- **PACKETS_TO_CAPTURE**: Total number of packets to capture (default: 70).
- **SYN_THRESHOLD**: Number of SYN packets from a single IP that triggers an alert (default: 20).
- **TIME_WINDOW**: Time window in seconds to monitor for SYN floods (default: 60).

## Example Email Alert
When a SYN flood is detected, you will receive an email like this

```To: receiver@example.com
From: sender@example.com
Subject: SYN Flood Detected from IP: 192.168.1.100

Potential SYN flood detected.

--------------------------------------------------
IP address: 192.168.1.100.
SYN Count: 25 under 60s.
Source Port: 53217
Destination Port: 80
--------------------------------------------------
```

## Troubleshooting
- **Error:** EMAIL_PASSWORD environment variable not set! Ensure that the environment variables for the email credentials are correctly set.
- **Couldn't open device:** ... Check if the network interface is correct. You may need to change "wlp0s20f3" to your network device name (e.g., "eth0" or "en0").