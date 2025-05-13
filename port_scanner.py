import socket
import threading
import json
import csv
import xml.etree.ElementTree as ET
import logging
import subprocess
import sys
import os

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import WebDriverException, TimeoutException

from scapy.all import IP, TCP, UDP, ICMP, sr1, conf

class PortScanner:
    def __init__(self, target, port_range, scan_type, timeout=1, threads=10):
        self.target = target
        self.port_range = port_range
        self.scan_type = scan_type
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.firewalled_ports = []
        self.web_servers = []
        self.lock = threading.Lock()
        
        self.screenshots_dir = 'web_screenshots'
        os.makedirs(self.screenshots_dir, exist_ok=True)
    
        logging.basicConfig(
            level=logging.INFO, 
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('scan.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.driver = None
        self.setup_webdriver()

    def setup_webdriver(self):
        """Initialize WebDriver for taking screenshots"""
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--log-level=3")  # Suppress logs

            # ✅ Use your locally installed ChromeDriver path
            chrome_driver_path = r"C:\Users\vakad\Downloads\PROJECT 6TH\Port Scanner\chromedriver.exe"

            # ✅ Start the WebDriver with the local path
            service = Service(chrome_driver_path)
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.set_page_load_timeout(10)  # Set page timeout
            
            logging.info("WebDriver initialized successfully")
        except Exception as e:
            logging.error(f"WebDriver setup error: {e}")
            self.driver = None



    def take_website_screenshot(self, url):
        """Capture screenshot of a web page"""
        try:
            if not self.driver:
                logging.warning("WebDriver not initialized")
                return None
            
            safe_filename = ''.join(c if c.isalnum() or c in ['-', '_'] else '_' for c in url)
            filename = os.path.join(self.screenshots_dir, f"{safe_filename}.png")
            
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(filename):
                filename = f"{base}_{counter}{ext}"
                counter += 1
            
            self.driver.get(url)
            
            self.driver.save_screenshot(filename)
            logging.info(f"Screenshot saved: {filename}")
            return filename
        except TimeoutException:
            logging.warning(f"Timeout loading {url}")
            return None
        except WebDriverException as e:
            logging.error(f"Screenshot error for {url}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected screenshot error for {url}: {e}")
            return None

    def detect_web_server(self, port):
        """Detect and screenshot web servers on common ports"""
        web_protocols = [
            f"http://{self.target}:{port}",
            f"https://{self.target}:{port}"
        ]
        
        for protocol in web_protocols:
            try:
                screenshot_path = self.take_website_screenshot(protocol)
                
                if screenshot_path:
                    web_server_info = {
                        'port': port,
                        'protocol': protocol,
                        'screenshot': screenshot_path
                    }
                    
                    with self.lock:
                        self.web_servers.append(web_server_info)
                    
                    logging.info(f"Web server detected: {protocol} on port {port}")
                    return web_server_info
            except Exception as e:
                logging.error(f"Web server detection error on {protocol}: {e}")
        
        return None

    def scan(self):
        try:
            self.target = socket.gethostbyname(self.target)
        except socket.gaierror:
            logging.error(f"Invalid target address: {self.target}")
            return

        conf.verb = 0

        threads = []
        for port in range(self.port_range[0], self.port_range[1] + 1):
            if len(threads) >= self.threads:
                for t in threads:
                    t.join()
                threads = []
            
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()

        for t in threads:
            t.join()

    def scan_port(self, port):
        try:
            if self.scan_type == "TCP":
                result = self.tcp_connect_scan(port)
            elif self.scan_type == "UDP":
                result = self.udp_scan(port)
            elif self.scan_type == "ACK":
                result = self.ack_scan(port)
            elif self.scan_type == "NULL":
                result = self.null_scan(port)
            elif self.scan_type == "XMAS":
                result = self.xmas_scan(port)
            elif self.scan_type == "FIN":
                result = self.fin_scan(port)
            elif self.scan_type == "SYN":
                result = self.syn_scan(port)
            
            return result
        except Exception as e:
            logging.error(f"Error scanning port {port}: {e}")
            return None

    def tcp_connect_scan(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                service = self.detect_service(port)
                
                web_ports = [80, 443, 8080, 8443]
                if port in web_ports:
                    self.detect_web_server(port)
                
                with self.lock:
                    self.results.append((port, service))
                    logging.info(f"Port {port} is open, Service: {service}")
            elif result == socket.timeout:
                with self.lock:
                    self.firewalled_ports.append(port)
                    logging.info(f"Port {port} is firewalled (no response).")
            sock.close()
        except Exception as e:
            logging.error(f"TCP connect scan error on port {port}: {e}")

    def udp_scan(self, port):
        try:
            protocols = [
                b'\x00' * 10,
                b'GET / HTTP/1.1\r\nHost: test\r\n\r\n',
                b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00',
            ]

            for payload in protocols:
                try:
                    packet = IP(dst=self.target)/UDP(dport=port)/payload
                    response = sr1(packet, timeout=self.timeout, verbose=0)
                    if response:
                        if response.haslayer(UDP):
                            with self.lock:
                                self.results.append((port, "UDP Open"))
                                logging.info(f"Port {port} is open (UDP scan)")
                            return
                        elif response.haslayer(ICMP):
                            with self.lock:
                                self.firewalled_ports.append(port)
                                logging.info(f"Port {port} is closed/filtered (UDP scan)")
                            return
                except Exception as payload_err:
                    logging.warning(f"Payload attempt failed for port {port}: {payload_err}")

            with self.lock:
                self.firewalled_ports.append(port)
                logging.info(f"Port {port} is filtered/open|filtered (UDP scan)")

        except Exception as e:
            logging.error(f"UDP scan comprehensive error on port {port}: {e}")

    def ack_scan(self, port):
        try:
            packet = IP(dst=self.target)/TCP(dport=port, flags="A")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                with self.lock:
                    self.firewalled_ports.append(port)
                    logging.info(f"Port {port} is filtered (no response to ACK)")
            elif response.haslayer(TCP):
                if response.haslayer(TCP) and response[TCP].flags == 'R':
                    with self.lock:
                        self.results.append((port, "ACK Scan"))
                        logging.info(f"Port {port} is unfiltered")
        except Exception as e:
            logging.error(f"ACK scan error on port {port}: {e}")

    def null_scan(self, port):
        try:
            packet = IP(dst=self.target)/TCP(dport=port, flags="")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                with self.lock:
                    self.results.append((port, "NULL Scan Open/Filtered"))
                    logging.info(f"Port {port} is open/filtered (NULL scan)")
            elif response.haslayer(TCP):
                if response[TCP].flags == 'R':
                    with self.lock:
                        logging.info(f"Port {port} is closed")
        except Exception as e:
            logging.error(f"NULL scan error on port {port}: {e}")

    def xmas_scan(self, port):
        try:
            packet = IP(dst=self.target)/TCP(dport=port, flags="FPU")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                with self.lock:
                    self.results.append((port, "XMAS Scan Open/Filtered"))
                    logging.info(f"Port {port} is open/filtered (XMAS scan)")
            elif response.haslayer(TCP):
                if response[TCP].flags == 'R':
                    with self.lock:
                        logging.info(f"Port {port} is closed")
        except Exception as e:
            logging.error(f"XMAS scan error on port {port}: {e}")

    def fin_scan(self, port):
        try:
            packet = IP(dst=self.target)/TCP(dport=port, flags="F")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                with self.lock:
                    self.results.append((port, "FIN Scan Open/Filtered"))
                    logging.info(f"Port {port} is open/filtered (FIN scan)")
            elif response.haslayer(TCP):
                if response[TCP].flags == 'R':
                    with self.lock:
                        logging.info(f"Port {port} is closed")
        except Exception as e:
            logging.error(f"FIN scan error on port {port}: {e}")

    def syn_scan(self, port):
        try:
            packet = IP(dst=self.target)/TCP(dport=port, flags="S")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is not None and response.haslayer(TCP):
                if response[TCP].flags == 'SA':
                    with self.lock:
                        self.results.append((port, "SYN Scan Open"))
                        logging.info(f"Port {port} is open (SYN scan)")
                elif response[TCP].flags == 'RA':
                    with self.lock:
                        logging.info(f"Port {port} is closed")
            else:
                with self.lock:
                    self.firewalled_ports.append(port)
                    logging.info(f"Port {port} is filtered/open|filtered")
        except Exception as e:
            logging.error(f"SYN scan error on port {port}: {e}")

    def detect_service(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return "Unknown"

    def check_firewall_rules(self):
        """Check firewall rules (for local system)."""
        try:
            if subprocess.run(["netsh", "advfirewall", "show", "allprofiles"], capture_output=True).returncode == 0:
                result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"], capture_output=True, text=True)
                return result.stdout
            else:
                return "Firewall rules could not be retrieved (non-Windows system)."
        except Exception as e:
            logging.error(f"Error checking firewall rules: {e}")
            return None

    def export_results(self, file_format):
        """Export scan results in specified format"""
        try:
            if file_format == 'json':
                with open('scan_results.json', 'w') as f:
                    export_data = {
                        'open_ports': self.results,
                        'firewalled_ports': self.firewalled_ports,
                        'web_servers': self.web_servers
                    }
                    json.dump(export_data, f, indent=4)

            elif file_format == 'csv':
                with open('scan_results.csv', 'w', newline='') as f:
                    writer = csv.writer(f)
                    
                    # Open Ports
                    writer.writerow(['Open Ports'])
                    writer.writerow(['Port', 'Service'])
                    for port, service in self.results:
                        writer.writerow([port, service])
                    
                    writer.writerow([])
                    writer.writerow(['Firewalled Ports'])
                    for port in self.firewalled_ports:
                        writer.writerow([port])
                    
                    writer.writerow([])
                    writer.writerow(['Web Servers'])
                    writer.writerow(['Port', 'Protocol', 'Screenshot'])
                    for server in self.web_servers:
                        writer.writerow([
                            server['port'], 
                            server['protocol'], 
                            server['screenshot']
                        ])

            elif file_format == 'xml':
                root = ET.Element("ScanResults")
                
                open_ports = ET.SubElement(root, "OpenPorts")
                for port, service in self.results:
                    port_element = ET.SubElement(open_ports, "Port")
                    port_element.set("number", str(port))
                    service_element = ET.SubElement(port_element, "Service")
                    service_element.text = service
                
                firewalled_element = ET.SubElement(root, "FirewalledPorts")
                for port in self.firewalled_ports:
                    port_element = ET.SubElement(firewalled_element, "Port")
                    port_element.text = str(port)
                
                web_servers_element = ET.SubElement(root, "WebServers")
                for server in self.web_servers:
                    server_element = ET.SubElement(web_servers_element, "Server")
                    ET.SubElement(server_element, "Port").text = str(server['port'])
                    ET.SubElement(server_element, "Protocol").text = server['protocol']
                    ET.SubElement(server_element, "Screenshot").text = server['screenshot']
                
                tree = ET.ElementTree(root)
                tree.write("scan_results.xml", encoding="utf-8", xml_declaration=True)

            logging.info(f"Results exported in {file_format} format")
        except Exception as e:
            logging.error(f"Export error: {e}")

    def __del__(self):
        """Close WebDriver when object is deleted"""
        try:
            if hasattr(self, 'driver') and self.driver:
                self.driver.quit()
                logging.info("WebDriver closed successfully")
        except Exception as e:
            logging.error(f"Error closing WebDriver: {e}")