# Advanced Port Scanner Toolkit 🚀

## 📌 Project Overview

The **Advanced Port Scanner Toolkit** is a powerful and user-friendly tool designed to scan open, closed, and firewalled ports of target IPs and domains. This toolkit also includes advanced capabilities such as geolocation detection, service identification, and interactive visualizations to enhance network reconnaissance and vulnerability analysis.

## 🔍 Features

- 🔎 **Scan Modes**:
  - TCP Connect Scan
  - SYN Scan
  - UDP Scan (optional module)
- 🌐 **Geolocation Detection**: Determine the physical location of the scanned IP.
- 📊 **Interactive Dashboard**: Displays open/closed ports in tabular format and maps.
- 🛡️ **Firewall Detection**: Identifies ports blocked by firewalls.
- 📜 **Export Results**: Save scan output in CSV or JSON format.

## 🧪 Tech Stack

- **Backend**: Python 3.x
- **Libraries**:
  - `socket`
  - `ipwhois`, `geopy`, `requests` for geolocation
  - `pandas`, `tabulate` for reporting
  - `argparse` for CLI
- **Optional**:
  - `scapy` for SYN/UDP scan
  - `folium` or `geopandas` for visual maps

## ⚙️ Installation

```bash
# Clone the repo
git clone https://github.com/your-username/advanced-port-scanner.git
cd advanced-port-scanner

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
