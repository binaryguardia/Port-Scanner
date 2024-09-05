import tkinter as tk
from tkinter import ttk, scrolledtext
import nmap
import socket
from threading import Thread

# Essential ports for filtering with associated common vulnerabilities (static data for demo)
essential_ports = {
    22: {'name': 'SSH', 'vulnerability': 'Weak Passwords, Outdated Versions'},
    80: {'name': 'HTTP', 'vulnerability': 'Insecure HTTP, Open Directories'},
    443: {'name': 'HTTPS', 'vulnerability': 'SSL Misconfigurations'},
    21: {'name': 'FTP', 'vulnerability': 'Anonymous Access, Cleartext Credentials'},
    53: {'name': 'DNS', 'vulnerability': 'DNS Cache Poisoning'},
    25: {'name': 'SMTP', 'vulnerability': 'Open Relays'},
    110: {'name': 'POP3', 'vulnerability': 'Cleartext Transmission of Credentials'},
    143: {'name': 'IMAP', 'vulnerability': 'Cleartext Transmission of Credentials'},
    3306: {'name': 'MySQL', 'vulnerability': 'Default Credentials, SQL Injection'},
    8080: {'name': 'HTTP-Proxy', 'vulnerability': 'Misconfigured Proxy'}
}

# Function to handle the scan button click
def start_scan():
    target = ip_entry.get()
    if not target:
        result_textbox.config(state=tk.NORMAL)
        result_textbox.delete(1.0, tk.END)
        result_textbox.insert(tk.END, "Please enter an IP address or domain name.")
        result_textbox.config(state=tk.DISABLED)
        return
    
    # Show scanning animation and a professional waiting message
    animation_label.config(text="🔍 Scanning... Please wait, this may take some time.", foreground="lime")
    root.update_idletasks()
    Thread(target=perform_scan, args=(target,)).start()

def perform_scan(target):
    try:
        # Convert domain name to IP if necessary
        ip_address = socket.gethostbyname(target)
        
        nm = nmap.PortScanner()
        nm.scan(ip_address, arguments='-T4')
        scan_results = f"Target: {target} ({ip_address})\n"
        
        # Scan only essential open ports
        for protocol in nm[ip_address].all_protocols():
            scan_results += f"\nProtocol: {protocol}\n"
            for port in nm[ip_address][protocol].keys():
                state = nm[ip_address][protocol][port]['state']
                if port in essential_ports and state == 'open':  # Filter only open ports
                    service = nm[ip_address][protocol][port]['name']
                    vulnerability = essential_ports[port]['vulnerability']
                    scan_results += (
                        f"Port: {port}\tState: {state}\tService: {essential_ports[port]['name']}\n"
                        f"Vulnerability: {vulnerability}\n"
                    )
        
        # Update GUI elements on the main thread
        root.after(0, lambda: update_gui(scan_results))
        
    except Exception as e:
        root.after(0, lambda: update_gui(f"Error: {str(e)}"))
    finally:
        root.after(0, lambda: animation_label.config(text="✔ Scan Complete", foreground="red"))

def update_gui(results):
    result_textbox.config(state=tk.NORMAL)
    result_textbox.delete(1.0, tk.END)
    result_textbox.insert(tk.END, results)
    result_textbox.config(state=tk.DISABLED)

# Create the main application window
root = tk.Tk()
root.title("Comprehensive Port Scanner with Vulnerability Insights")
root.geometry("900x700")
root.configure(bg='black')

# Create a canvas for the background
canvas = tk.Canvas(root, width=900, height=700)
canvas.pack(fill="both", expand=True)

# Gradient background function
def draw_gradient(canvas):
    for i in range(256):
        r = hex(0)[2:].zfill(2)
        g = hex(i)[2:].zfill(2)
        b = hex(0)[2:].zfill(2)
        color = f"#{r}{g}{b}"
        canvas.create_line(0, i * 2, 900, i * 2, fill=color)

draw_gradient(canvas)

# Create a frame to hold all widgets, placed on top of the canvas
frame = tk.Frame(canvas, bg="black")
frame.place(relwidth=1, relheight=1)

# Add a label for the title with animation effect
title_label = ttk.Label(frame, text="Port Scanner with Vulnerabilities", font=("Helvetica", 26, "bold"), foreground="lime", background="black")
title_label.pack(pady=10)

# Add an entry widget for IP address or domain name input
ip_label = ttk.Label(frame, text="Enter IP Address or Domain Name:", font=("Helvetica", 16), foreground="cyan", background="black")
ip_label.pack(pady=5)
ip_entry = ttk.Entry(frame, width=60, font=("Helvetica", 16))
ip_entry.pack(pady=5)

# Add a button to start the scan
scan_button = ttk.Button(frame, text="Start Scan", command=start_scan, style="TButton")
scan_button.pack(pady=10)

# Add a label to display scanning animation and message
animation_label = ttk.Label(frame, text="", font=("Helvetica", 18), foreground="lime", background="black")
animation_label.pack(pady=10)

# Add a scrolled text widget to display scan results
result_textbox = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=("Helvetica", 16), foreground="white", background="black", height=15)
result_textbox.pack(pady=10, fill=tk.BOTH, expand=True)
result_textbox.config(state=tk.DISABLED)

# Define the button style
style = ttk.Style()
style.configure("TButton", font=("Helvetica", 16, "bold"), padding=10, background="green", foreground="black")
style.map("TButton", background=[("active", "lime")])

# Run the application
root.mainloop()
