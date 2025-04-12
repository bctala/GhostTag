# 👻 GhostTag: The Phantom Packet Flagger

GhostTag is a Python tool for capturing network traffic, embedding custom flags into packets, and analyzing flagged packets. It leverages the [Scapy](https://scapy.net/) library for packet manipulation and analysis.

## Features

- **Packet Sniffing**: Captures live network traffic for a specified duration.
- **Flag Embedding**: Adds user-defined flags to random packets in the captured traffic.
- **Packet Analysis**: Identifies and analyzes packets containing the embedded flags.
- **Protocol Distribution**: Displays a breakdown of protocols in the captured traffic.
- **Detailed Packet Information**: Provides summaries and detailed information for flagged packets.

---

## 🛠 Requirements

- Python 3.x
- [`Scapy`](https://scapy.readthedocs.io/) library  
  Install via pip:
  ```bash
  pip install scapy
  ```

---

## 🚀 How to Run

```bash
python GhostTag.py
```

Then follow the prompts:
1. Enter the number of flags.
2. Enter each flag in the format `FlagX{your_flag}`.
3. Let the tool sniff for 30 seconds and insert flags.
4. Analyze the results printed in the terminal.

---

## 📦 Output

- A file called `traffic_with_flags.pcap` will be saved in your current directory.
- You can open it with tools like **Wireshark** to inspect how flags were embedded into real traffic.

---

## 📌 Example Flag

```
FlagX{you_found_me}
```

---

## 📋 Use Cases

- Building **CTF challenges** where flags must be extracted from network traffic.
- **Training** students in packet analysis and threat detection.
- Demonstrating **steganography in network protocols**.

---

## ⚠️ Disclaimer

GhostTag is for educational and ethical use only. Do not use it on networks without explicit permission.

---

## ✨ Author

Created by [Tala Almulla] for educational cybersecurity projects.
```
