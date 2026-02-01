import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import queue
from datetime import datetime
from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
import os

# --- IMPORT THE OTHER MODULES ---
import flow_converter
import traffic_analyzer

# --- Configuration ---
# Make sure these names match your file names exactly
MODEL_FILE = "random_forest_model.pkl"
ENCODER_FILE = "label_encoder.pkl"

TCP_PORT_MAP = {
    20: "FTP-Data", 21: "FTP-Ctrl", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3389: "RDP",
}

packet_queue = queue.Queue()


class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Traffic Analyzer System")
        self.root.geometry("1400x800")

        # Check files on startup
        if not os.path.exists(MODEL_FILE):
            messagebox.showwarning("Warning", f"Model file '{MODEL_FILE}' not found!")

        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("Treeview", rowheight=30, font=("Segoe UI", 12))
        style.configure("Treeview.Heading", font=("Segoe UI", 13, 'bold'))

        self.sniffing = False
        self.sniffing_thread = None
        self.all_packets_gui_data = []
        self.packet_details = {}
        self.raw_packets = []

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        # Top Frame
        top_frame = ttk.Frame(root, padding="10")
        top_frame.grid(row=0, column=0, sticky="ew")

        # Buttons
        self.start_button = ttk.Button(top_frame, text="Start Sniffing", command=self.start_sniffing, width=15)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = ttk.Button(top_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED,
                                      width=15)
        self.stop_button.grid(row=0, column=1, padx=5)

        # === THE MAGIC BUTTON ===
        self.analyze_button = ttk.Button(top_frame, text="Stop & Analyze", command=self.stop_and_analyze,
                                         state=tk.DISABLED, width=20)
        self.analyze_button.grid(row=0, column=2, padx=5)
        # ========================

        ttk.Separator(top_frame, orient='vertical').grid(row=0, column=3, sticky='ns', padx=15)

        filter_label = ttk.Label(top_frame, text="Filter:")
        filter_label.grid(row=0, column=4, sticky='e')
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", self.apply_filter)
        ttk.Entry(top_frame, textvariable=self.filter_var, width=30).grid(row=0, column=5, padx=5)

        ttk.Button(top_frame, text="Clear", command=self.clear_all).grid(row=0, column=6, padx=10)

        # Treeview
        tree_frame = ttk.Frame(root, padding=(10, 0, 10, 10))
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        columns = ("#", "Time", "Protocol", "Src IP", "Dst IP")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=140)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        scrollbar.grid(row=0, column=1, sticky='ns')

        self.root.after(100, self.process_queue)

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.analyze_button.config(state=tk.NORMAL)
        self.sniffing_thread = threading.Thread(target=self.packet_sniffer, daemon=True)
        self.sniffing_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.analyze_button.config(state=tk.DISABLED)

    def stop_and_analyze(self):
        """
        1. Stops sniffing.
        2. Saves PCAP.
        3. Converts to CSV.
        4. Runs Analysis.
        """
        self.stop_sniffing()

        if not self.raw_packets:
            messagebox.showinfo("Info", "No packets captured!")
            return

        # Ask user where to save the capture
        pcap_filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap")],
            title="Save Capture to Analyze"
        )

        if pcap_filename:
            try:
                # 1. Save PCAP
                print(f"Saving {len(self.raw_packets)} packets...")
                wrpcap(pcap_filename, self.raw_packets)

                # 2. Convert to CSV
                csv_filename = pcap_filename.replace(".pcap", ".csv")
                success = flow_converter.pcap_to_csv(pcap_filename, csv_filename)

                if success:
                    # 3. Run Analysis
                    messagebox.showinfo("Success", "Processing complete.\nStarting Analysis Graphs...")
                    traffic_analyzer.analyze_traffic(csv_filename, MODEL_FILE, ENCODER_FILE)
                else:
                    messagebox.showerror("Error", "Conversion to CSV failed.")

            except Exception as e:
                messagebox.showerror("Error", f"Process failed: {e}")

    def packet_sniffer(self):
        sniff(prn=lambda packet: packet_queue.put(packet), stop_filter=lambda x: not self.sniffing)

    def process_queue(self):
        BATCH_SIZE = 50
        count = 0
        while not packet_queue.empty() and count < BATCH_SIZE:
            try:
                packet = packet_queue.get_nowait()
                self.add_packet_to_gui(packet)
                count += 1
            except:
                pass
        self.root.after(100, self.process_queue)

    def add_packet_to_gui(self, packet):
        self.raw_packets.append(packet)
        packet_count = len(self.all_packets_gui_data) + 1
        time_str = datetime.now().strftime("%H:%M:%S")

        proto = "Other"
        src_ip = "N/A"
        dst_ip = "N/A"

        if packet.haslayer(IP):
            src_ip, dst_ip = packet[IP].src, packet[IP].dst
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ARP):
            proto = "ARP"

        values = (packet_count, time_str, proto, src_ip, dst_ip)
        self.tree.insert('', 'end', values=values)
        self.all_packets_gui_data.append(values)

        # Auto scroll if near bottom
        if len(self.tree.get_children()) > 0:
            self.tree.yview_moveto(1.0)

    def apply_filter(self, *args):
        pass  # Simplified for brevity

    def clear_all(self):
        self.tree.delete(*self.tree.get_children())
        self.raw_packets.clear()
        self.all_packets_gui_data.clear()


if __name__ == "__main__":
    app_root = tk.Tk()
    gui = PacketSnifferGUI(app_root)
    app_root.mainloop()