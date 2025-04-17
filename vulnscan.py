import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import threading
import nmap  # pip install python-nmap
import requests
import subprocess
from scapy.all import ARP, Ether, srp  # pip install scapy
import os

def update_status(message):
    """ Updates the status label with progress information. """
    status_label.config(text=f"Status: {message}")
    root.update_idletasks()

def run_port_scan(target):
    scanner = nmap.PortScanner()
    result = f"Port Scan Results for {target}:\n"
    update_status("Starting Port Scan...")
    try:
        scanner.scan(hosts=target, arguments='-sV -O')  # OS detection & service enumeration
        for host in scanner.all_hosts():
            result += f"\nHost: {host} ({scanner[host].hostname()})\n"
            result += f"State: {scanner[host].state()}\n"
            if 'osmatch' in scanner[host]:
                result += f"OS Detected: {scanner[host]['osmatch'][0]['name']}\n"
            for proto in scanner[host].all_protocols():
                result += f"Protocol: {proto}\n"
                for port in sorted(scanner[host][proto].keys()):
                    info = scanner[host][proto][port]
                    result += f"Port: {port}  State: {info.get('state','')}  Service: {info.get('name','')}\n"
    except Exception as e:
        result += f"Error in port scan: {e}\n"
    update_status("Port Scan Complete.")
    return result

def run_web_scan(target):
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
    result = f"Web Scan Results for {target}:\n"
    update_status("Starting Web Scan...")

    try:
        # HTTP Headers
        response = requests.get(target, timeout=10)
        result += "HTTP Headers:\n"
        for k, v in response.headers.items():
            result += f"{k}: {v}\n"

        # Technology Identification (WhatWeb)
        whatweb_cmd = f"whatweb {target} --quiet"
        try:
            whatweb_output = subprocess.check_output(whatweb_cmd, shell=True, text=True)
            result += f"\n[WhatWeb] Technology Fingerprint:\n{whatweb_output.strip()}\n"
        except Exception as e:
            result += f"[WhatWeb] Error: {e}\n"

        # Hidden Directories (Gobuster alternative: dirb)
        dirb_cmd = f"dirb {target} -w"
        try:
            dirb_output = subprocess.check_output(dirb_cmd, shell=True, text=True)
            result += f"\n[Hidden Directories] Results:\n{dirb_output.strip()}\n"
        except Exception as e:
            result += f"[Hidden Directories] Error: {e}\n"

        # Vulnerability Scan (Nikto)
        nikto_cmd = f"nikto -h {target}"
        try:
            nikto_output = subprocess.check_output(nikto_cmd, shell=True, text=True)
            result += f"\n[Nikto] Vulnerability Scan:\n{nikto_output.strip()}\n"
        except Exception as e:
            result += f"[Nikto] Error: {e}\n"

    except Exception as e:
        result += f"Error in web scan: {e}\n"

    update_status("Web Scan Complete.")
    return result

def run_iot_scan(target):
    result = f"IoT Scan Results for {target}:\n"
    update_status("Scanning for IoT Devices...")
    try:
        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered, _ = srp(packet, timeout=2, verbose=0)
        if answered:
            for sent, received in answered:
                result += f"IP: {received.psrc}  MAC: {received.hwsrc}\n"
        else:
            result += "No live IoT devices found.\n"
    except Exception as e:
        result += f"Error in IoT scan: {e}\n"
    update_status("IoT Scan Complete.")
    return result

def run_scan(scan_function, target):
    output_text.delete(1.0, tk.END)
    result = scan_function(target)
    output_text.insert(tk.END, result)

def threaded_scan(scan_function, target):
    threading.Thread(target=run_scan, args=(scan_function, target)).start()

def generate_report():
    report = output_text.get(1.0, tk.END)
    if not report.strip():
        messagebox.showerror("Error", "No report data available.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as f:
            f.write(report)
        messagebox.showinfo("Report Saved", f"Report saved to {file_path}")

# Create the main window
root = tk.Tk()
root.title("VulnXplorer")
root.geometry("1000x700")
root.configure(bg="#2C3E50")

# Left dashboard frame
dashboard_frame = tk.Frame(root, bg="#34495E", width=250)
dashboard_frame.pack(side="left", fill="y")

# Main content frame
content_frame = tk.Frame(root, bg="#2C3E50")
content_frame.pack(side="right", fill="both", expand=True)

# Top frame in content for target entry
target_frame = tk.Frame(content_frame, bg="#2C3E50")
target_frame.pack(pady=10)

target_label = tk.Label(target_frame, text="Enter Target IP/Range/URL:", bg="#2C3E50", fg="white", font=("Helvetica", 12))
target_label.pack(side="left", padx=5)
target_entry = tk.Entry(target_frame, width=40, font=("Helvetica", 12))
target_entry.pack(side="left", padx=5)

# Status label
status_label = tk.Label(content_frame, text="Status: Idle", bg="#2C3E50", fg="yellow", font=("Helvetica", 12, "bold"))
status_label.pack(pady=5)

# Dashboard buttons
btn_iot = tk.Button(dashboard_frame, text="IoT Scan", width=20, bg="#E74C3C", fg="white",
                    command=lambda: threaded_scan(run_iot_scan, target_entry.get().strip()))
btn_iot.pack(pady=10, padx=10)

btn_web = tk.Button(dashboard_frame, text="Web Scan", width=20, bg="#3498DB", fg="white",
                    command=lambda: threaded_scan(run_web_scan, target_entry.get().strip()))
btn_web.pack(pady=10, padx=10)

btn_port = tk.Button(dashboard_frame, text="Port Scan", width=20, bg="#2ECC71", fg="white",
                     command=lambda: threaded_scan(run_port_scan, target_entry.get().strip()))
btn_port.pack(pady=10, padx=10)

btn_report = tk.Button(dashboard_frame, text="Generate Report", width=20, bg="#F1C40F", fg="black",
                       command=generate_report)
btn_report.pack(pady=10, padx=10)

# Scrolled text widget for scan output
output_text = scrolledtext.ScrolledText(content_frame, font=("Courier", 10), bg="black", fg="lime")
output_text.pack(fill="both", expand=True, padx=10, pady=10)

root.mainloop()