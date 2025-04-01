#!/usr/bin/env python3
import socket
import threading
from tkinter import *
from tkinter import ttk, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import ipaddress
from datetime import datetime

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberPort Scanner")
        self.root.geometry("800x600")
        self.style = ttk.Style(theme="cyborg")  # Cool dark theme
        
        # Configure grid
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(2, weight=1)
        
        # Header
        self.header = ttk.Label(
            self.root, 
            text="CYBER PORT SCANNER", 
            font=("Helvetica", 18, "bold"),
            bootstyle="primary"
        )
        self.header.grid(row=0, column=0, pady=10, sticky="n")
        
        # Input Frame
        input_frame = ttk.Frame(self.root)
        input_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        
        # Target IP
        ttk.Label(input_frame, text="Target IP:").grid(row=0, column=0, padx=5, sticky="e")
        self.ip_entry = ttk.Entry(input_frame, width=20)
        self.ip_entry.grid(row=0, column=1, padx=5, sticky="w")
        self.ip_entry.insert(0, "127.0.0.1")  # Default to localhost
        
        # Port Range
        ttk.Label(input_frame, text="Port Range:").grid(row=1, column=0, padx=5, sticky="e")
        self.start_port = ttk.Entry(input_frame, width=8)
        self.start_port.grid(row=1, column=1, padx=5, sticky="w")
        self.start_port.insert(0, "1")
        
        ttk.Label(input_frame, text="to").grid(row=1, column=2, padx=5)
        self.end_port = ttk.Entry(input_frame, width=8)
        self.end_port.grid(row=1, column=3, padx=5, sticky="w")
        self.end_port.insert(0, "1024")  # Default to well-known ports
        
        # Threads
        ttk.Label(input_frame, text="Threads:").grid(row=2, column=0, padx=5, sticky="e")
        self.threads = ttk.Scale(
            input_frame, 
            from_=1, 
            to=500, 
            value=100,
            orient=HORIZONTAL,
            bootstyle="primary"
        )
        self.threads.grid(row=2, column=1, columnspan=3, padx=5, sticky="ew")
        self.thread_label = ttk.Label(input_frame, text="100")
        self.thread_label.grid(row=2, column=4, padx=5)
        self.threads.configure(command=self.update_thread_label)
        
        # Buttons
        self.scan_btn = ttk.Button(
            input_frame, 
            text="Start Scan", 
            command=self.start_scan,
            bootstyle="success"
        )
        self.scan_btn.grid(row=3, column=1, pady=10, sticky="w")
        
        self.stop_btn = ttk.Button(
            input_frame, 
            text="Stop Scan", 
            command=self.stop_scan,
            bootstyle="danger",
            state=DISABLED
        )
        self.stop_btn.grid(row=3, column=2, pady=10, padx=5, sticky="w")
        
        # Results Frame
        results_frame = ttk.Frame(self.root)
        results_frame.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(1, weight=1)
        
        # Progress Bar
        self.progress = ttk.Progressbar(
            results_frame, 
            orient=HORIZONTAL, 
            mode='determinate',
            bootstyle="success-striped"
        )
        self.progress.grid(row=0, column=0, sticky="ew", pady=5)
        
        # Results Treeview
        columns = ("port", "status", "service")
        self.results_tree = ttk.Treeview(
            results_frame, 
            columns=columns, 
            show="headings",
            bootstyle="primary"
        )
        
        self.results_tree.heading("port", text="Port")
        self.results_tree.heading("status", text="Status")
        self.results_tree.heading("service", text="Service")
        
        self.results_tree.column("port", width=100, anchor="center")
        self.results_tree.column("status", width=100, anchor="center")
        self.results_tree.column("service", width=200, anchor="w")
        
        scrollbar = ttk.Scrollbar(
            results_frame, 
            orient=VERTICAL, 
            command=self.results_tree.yview
        )
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.grid(row=1, column=0, sticky="nsew")
        scrollbar.grid(row=1, column=1, sticky="ns")
        
        # Status Bar
        self.status_var = StringVar()
        self.status_var.set("Ready to scan")
        self.status_bar = ttk.Label(
            self.root, 
            textvariable=self.status_var,
            relief=SUNKEN,
            anchor=W,
            bootstyle="secondary"
        )
        self.status_bar.grid(row=3, column=0, sticky="ew", padx=5, pady=5)
        
        # Scan control variables
        self.scanning = False
        self.stop_requested = False
        
        # Common ports dictionary
        self.common_ports = {
            20: "FTP (Data)",
            21: "FTP (Control)",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            # Add more as needed
        }
    
    def update_thread_label(self, value):
        self.thread_label.config(text=f"{float(value):.0f}")
    
    def validate_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def get_service_name(self, port):
        return self.common_ports.get(port, "Unknown")
    
    def scan_port(self, ip, port):
        if self.stop_requested:
            return None
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    return port
        except (socket.timeout, socket.error):
            pass
        return None
    
    def scan_worker(self, ip, ports, progress_callback):
        open_ports = []
        total_ports = len(ports)
        
        for i, port in enumerate(ports):
            if self.stop_requested:
                break
                
            result = self.scan_port(ip, port)
            if result is not None:
                open_ports.append(result)
                service = self.get_service_name(port)
                self.results_tree.insert("", "end", values=(port, "OPEN", service))
            
            # Update progress
            progress = (i + 1) / total_ports * 100
            self.root.after(10, lambda: progress_callback(progress))
        
        self.root.after(10, self.scan_complete)
    
    def start_scan(self):
        # Validate inputs
        ip = self.ip_entry.get()
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Invalid IP address")
            return
        
        try:
            start_port = int(self.start_port.get())
            end_port = int(self.end_port.get())
            if not (1 <= start_port <= end_port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Invalid port range (1-65535)")
            return
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Setup UI for scanning
        self.scanning = True
        self.stop_requested = False
        self.scan_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.progress["value"] = 0
        self.status_var.set("Scanning in progress...")
        
        # Get ports to scan
        ports = range(start_port, end_port + 1)
        
        # Start scan in separate thread
        scan_thread = threading.Thread(
            target=self.scan_worker,
            args=(ip, ports, self.update_progress),
            daemon=True
        )
        scan_thread.start()
    
    def stop_scan(self):
        self.stop_requested = True
        self.status_var.set("Scan stopped by user")
    
    def scan_complete(self):
        self.scanning = False
        self.scan_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        
        if not self.stop_requested:
            self.status_var.set("Scan completed successfully")
            self.progress["value"] = 100
        else:
            self.status_var.set("Scan stopped by user")
    
    def update_progress(self, value):
        self.progress["value"] = value
        self.status_var.set(f"Scanning... {value:.1f}% complete")

if __name__ == "__main__":
    root = ttk.Window(themename="cyborg")
    app = PortScannerGUI(root)
    root.mainloop()
