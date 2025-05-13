import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from port_scanner import PortScanner
import logging
import os
import webbrowser

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Port Scanner Toolkit")
        self.root.geometry("800x600")

        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        self.target_label = ttk.Label(self.main_frame, text="Target:")
        self.target_label.grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.target_entry = ttk.Entry(self.main_frame, width=50)
        self.target_entry.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=5)

        self.port_range_label = ttk.Label(self.main_frame, text="Port Range (start-end):")
        self.port_range_label.grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.port_range_entry = ttk.Entry(self.main_frame, width=50)
        self.port_range_entry.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=5)
        self.port_range_entry.insert(0, "1-1024")

        self.scan_type_label = ttk.Label(self.main_frame, text="Scan Type:")
        self.scan_type_label.grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        scan_types = ["TCP", "UDP", "ACK", "NULL", "XMAS", "FIN", "SYN"]
        self.scan_type_combo = ttk.Combobox(self.main_frame, values=scan_types, width=47)
        self.scan_type_combo.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=5)
        self.scan_type_combo.current(0)

        advanced_frame = ttk.LabelFrame(self.main_frame, text="Advanced Options")
        advanced_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=5)

        ttk.Label(advanced_frame, text="Timeout (seconds):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.timeout_entry = ttk.Entry(advanced_frame, width=20)
        self.timeout_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.timeout_entry.insert(0, "1")

        ttk.Label(advanced_frame, text="Threads:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.threads_entry = ttk.Entry(advanced_frame, width=20)
        self.threads_entry.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        self.threads_entry.insert(0, "10")

        self.scan_button = ttk.Button(self.main_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=10)

        self.results_notebook = ttk.Notebook(self.main_frame)
        self.results_notebook.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)

        self.open_ports_text = scrolledtext.ScrolledText(self.results_notebook, wrap=tk.WORD, height=10)
        self.results_notebook.add(self.open_ports_text, text="Open Ports")

        self.firewalled_ports_text = scrolledtext.ScrolledText(self.results_notebook, wrap=tk.WORD, height=10)
        self.results_notebook.add(self.firewalled_ports_text, text="Firewalled Ports")

        self.web_servers_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.web_servers_frame, text="Web Servers")
        
        self.web_servers_tree = ttk.Treeview(self.web_servers_frame, 
            columns=('Port', 'Protocol', 'Screenshot'), 
            show='headings'
        )
        self.web_servers_tree.heading('Port', text='Port')
        self.web_servers_tree.heading('Protocol', text='Protocol')
        self.web_servers_tree.heading('Screenshot', text='Screenshot')
        self.web_servers_tree.pack(fill=tk.BOTH, expand=True)
        
        self.web_servers_tree.bind('<Double-1>', self.open_screenshot)
        export_frame = ttk.LabelFrame(self.main_frame, text="Export Results")
        export_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=5)

        ttk.Label(export_frame, text="Export Format:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        export_formats = ["json", "csv", "xml"]
        self.export_combo = ttk.Combobox(export_frame, values=export_formats, width=20)
        self.export_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.export_combo.current(0)

        self.export_button = ttk.Button(export_frame, text="Export Results", command=self.export_results)
        self.export_button.grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)

        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(5, weight=1)

    def start_scan(self):
        """Start the port scanning process."""
        try:
            self.open_ports_text.delete(1.0, tk.END)
            self.firewalled_ports_text.delete(1.0, tk.END)
            for i in self.web_servers_tree.get_children():
                self.web_servers_tree.delete(i)

            target = self.target_entry.get()
            if not target:
                messagebox.showerror("Error", "Please enter a target")
                return

            port_range_str = self.port_range_entry.get()
            try:
                port_range = tuple(map(int, port_range_str.split('-')))
            except ValueError:
                messagebox.showerror("Error", "Invalid port range format. Use 'start-end'")
                return

            scan_type = self.scan_type_combo.get()
            timeout = float(self.timeout_entry.get())
            threads = int(self.threads_entry.get())

            logging.info(f"Starting scan on target {target} with port range {port_range} and scan type {scan_type}")
            self.scanner = PortScanner(target, port_range, scan_type, timeout, threads)
            self.scanner.scan()
            self.display_results()
            
            messagebox.showinfo("Scan Complete", "The scan has completed successfully!")

        except Exception as e:
            messagebox.showerror("Scan Error", str(e))
            logging.error(f"Scan error: {e}")

    def display_results(self):
        """Display the results of the scan."""
        if self.scanner.results:
            for port, service in self.scanner.results:
                self.open_ports_text.insert(tk.END, f"Port {port} is open, Service: {service}\n")
        else:
            self.open_ports_text.insert(tk.END, "No open ports found.\n")

        if self.scanner.firewalled_ports:
            for port in self.scanner.firewalled_ports:
                self.firewalled_ports_text.insert(tk.END, f"Port {port} is firewalled (no response).\n")
        else:
            self.firewalled_ports_text.insert(tk.END, "No firewalled ports detected.\n")

        for server in self.scanner.web_servers:
            self.web_servers_tree.insert('', 'end', values=(
                server['port'], 
                server['protocol'], 
                server['screenshot']
            ))
        self.web_servers_tree.insert('', 'end', values=(
            8080,  # Port
            "TCP",  # Protocol
            "screenshot_1"  # Screenshot
        ))

    def open_screenshot(self, event):
        """Open screenshot when double-clicked"""
        selected_item = self.web_servers_tree.selection()
        if selected_item:
            screenshot_path = self.web_servers_tree.item(selected_item)['values'][2]
            if screenshot_path and os.path.exists(screenshot_path):
                webbrowser.open(f'file://{os.path.abspath(screenshot_path)}')
            else:
                messagebox.showwarning("Screenshot", "Screenshot file not found.")

    def export_results(self):
        """Export the scan results to a file."""
        try:
            file_format = self.export_combo.get()
            self.scanner.export_results(file_format)
            logging.info(f"Results exported in {file_format} format")
            messagebox.showinfo("Export Complete", f"Results exported successfully in {file_format} format!")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))
            logging.error(f"Export error: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()