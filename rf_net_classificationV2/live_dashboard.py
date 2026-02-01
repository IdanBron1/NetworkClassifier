import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import pandas as pd
import joblib
import os
import datetime
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# --- IMPORTS ---
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


# ==========================================
# CONFIGURATION
# ==========================================
MODEL_FILE = "random_forest_model.pkl"
ENCODER_FILE = "label_encoder.pkl"
UPDATE_INTERVAL = 3000  # 3 seconds
FLOW_TIMEOUT = 30  # Keep flows for 30s
MAX_PACKETS_DISPLAY = 50

# --- THEME SETTINGS ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class ModernNetWatch(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("NetWatch Pro // Cyber Analytics Suite")
        self.geometry("1400x900")

        # Data & Models
        self.model = None
        self.encoder = None
        self.load_models()
        self.flows = {}
        self.sniffing = False
        self.packet_count = 0

        # Note: We removed packet_history list because we will export Flows now (Smarter)

        # Layout Setup
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.setup_sidebar()
        self.setup_main_area()

    def load_models(self):
        try:
            if os.path.exists(MODEL_FILE) and os.path.exists(ENCODER_FILE):
                self.model = joblib.load(MODEL_FILE)
                self.encoder = joblib.load(ENCODER_FILE)
                print(">> SYSTEM: Models Loaded.")
            else:
                messagebox.showwarning("System Error", "Model files not found!")
        except Exception as e:
            print(f"Error: {e}")

    def setup_sidebar(self):
        # --- LEFT SIDEBAR ---
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        self.logo_label = ctk.CTkLabel(self.sidebar, text="NetWatch\nPRO EDITION",
                                       font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.status_label = ctk.CTkLabel(self.sidebar, text="STATUS: STANDBY", text_color="gray")
        self.status_label.grid(row=1, column=0, padx=20, pady=10)

        self.btn_start = ctk.CTkButton(self.sidebar, text="▶ START MONITORING", command=self.start_sniffing,
                                       fg_color="#2ecc71", hover_color="#27ae60")
        self.btn_start.grid(row=2, column=0, padx=20, pady=10)

        self.btn_stop = ctk.CTkButton(self.sidebar, text="■ STOP SYSTEM", command=self.stop_sniffing, state="disabled",
                                      fg_color="#e74c3c", hover_color="#c0392b")
        self.btn_stop.grid(row=3, column=0, padx=20, pady=10)

        self.btn_export = ctk.CTkButton(self.sidebar, text="⬇ EXPORT REPORT", command=self.export_final_report,
                                        fg_color="#3498db", hover_color="#2980b9")
        self.btn_export.grid(row=4, column=0, padx=20, pady=(30, 10))

        self.footer_label = ctk.CTkLabel(self.sidebar, text="v3.0.0", font=ctk.CTkFont(size=10))
        self.footer_label.grid(row=9, column=0, padx=20, pady=20, sticky="s")
        self.sidebar.grid_rowconfigure(9, weight=1)

    def setup_main_area(self):
        # --- RIGHT MAIN AREA ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # 1. Graphs
        self.graph_container = ctk.CTkFrame(self.main_frame)
        self.graph_container.grid(row=0, column=0, sticky="nsew", pady=(0, 20))
        self.setup_matplotlib()

        # 2. List
        self.list_container = ctk.CTkFrame(self.main_frame)
        self.list_container.grid(row=1, column=0, sticky="nsew")

        lbl = ctk.CTkLabel(self.list_container, text=" LIVE PACKET STREAM (Raw Data)",
                           font=ctk.CTkFont(size=14, weight="bold"), anchor="w")
        lbl.pack(fill="x", padx=10, pady=5)

        self.setup_treeview()

    def setup_matplotlib(self):
        plt.style.use('dark_background')
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(10, 4))
        self.fig.patch.set_facecolor('#2b2b2b')
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_container)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=5)

    def setup_treeview(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", rowheight=25,
                        borderwidth=0)
        style.configure("Treeview.Heading", background="#1f1f1f", foreground="white", relief="flat")
        style.map("Treeview", background=[('selected', '#3498db')])

        columns = ("#", "Time", "Proto", "Source", "Destination", "Length")
        self.tree = ttk.Treeview(self.list_container, columns=columns, show='headings', height=8)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")

        self.tree.column("#", width=50)
        self.tree.column("Length", width=60)

        scrollbar = ttk.Scrollbar(self.list_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar.pack(side="right", fill="y", pady=5)

    def start_sniffing(self):
        self.sniffing = True
        self.flows = {}
        self.packet_count = 0
        for i in self.tree.get_children(): self.tree.delete(i)

        self.btn_start.configure(state="disabled", text="RUNNING...")
        self.btn_stop.configure(state="normal")
        self.status_label.configure(text="STATUS: ● ACTIVE", text_color="#2ecc71")

        threading.Thread(target=self.packet_sniffer, daemon=True).start()
        self.update_graphs_loop()

    def stop_sniffing(self):
        self.sniffing = False
        self.btn_start.configure(state="normal", text="▶ START MONITORING")
        self.btn_stop.configure(state="disabled")
        self.status_label.configure(text="STATUS: STOPPED", text_color="gray")

    def export_final_report(self):
        """
        FIX 1: Export Analyzed Flows instead of Raw Packets
        This solves the 'Analyzing...' issue because we export the final state.
        """
        if not self.flows:
            messagebox.showinfo("Info", "No data to export yet.")
            return

        # 1. Convert flows to DataFrame
        df = pd.DataFrame(self.flows.values())
        if df.empty: return

        # 2. Add duration and port info
        df['duration'] = df['last_seen'] - df['start_time']

        # 3. RUN LOGIC ONE LAST TIME (To ensure Excel has latest classes)
        df = self.apply_logic(df)

        # 4. Prepare clean export
        export_df = df[['protocol', 'dst_port', 'fwd_bytes', 'bwd_bytes', 'duration', 'PREDICTED_CLASS']].copy()
        export_df['Total_Bytes'] = export_df['fwd_bytes'] + export_df['bwd_bytes']

        file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")],
                                                 title="Save Flow Report")
        if file_path:
            try:
                export_df.to_excel(file_path, index=False)
                messagebox.showinfo("Success", f"Professional Report Saved!\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")

    def packet_sniffer(self):
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.sniffing, store=0)

    def process_packet(self, pkt):
        if not pkt.haslayer(IP): return
        try:
            ip = pkt[IP];
            ts = time.time();
            length = len(pkt)
            proto_num = ip.proto
            sport, dport = 0, 0
            if pkt.haslayer(TCP):
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
            elif pkt.haslayer(UDP):
                sport, dport = pkt[UDP].sport, pkt[UDP].dport

            if ip.src < ip.dst:
                key = (ip.src, sport, ip.dst, dport, proto_num)
                direction = 'fwd'
            else:
                key = (ip.dst, dport, ip.src, sport, proto_num)
                direction = 'bwd'

            if key not in self.flows:
                self.flows[key] = {
                    'start_time': ts, 'last_seen': ts,
                    'fwd_pkts': 0, 'bwd_pkts': 0, 'fwd_bytes': 0, 'bwd_bytes': 0,
                    'fwd_iat_max': 0.0, 'dst_port': key[3] if direction == 'fwd' else key[1],
                    'protocol': proto_num,
                    'PREDICTED_CLASS': 'Analyzing...'
                }

            flow = self.flows[key]
            flow['fwd_iat_max'] = max(flow['fwd_iat_max'], ts - flow['last_seen'])
            flow['last_seen'] = ts

            if direction == 'fwd':
                flow['fwd_pkts'] += 1; flow['fwd_bytes'] += length
            else:
                flow['bwd_pkts'] += 1; flow['bwd_bytes'] += length

            self.packet_count += 1
            if self.packet_count % 5 == 0:
                time_s = datetime.datetime.now().strftime("%H:%M:%S")
                proto_str = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else str(proto_num))

                # Live list shows Raw Data (Packet) not Class (Flow) to avoid confusion
                self.tree.insert('', 0, values=(self.packet_count, time_s, proto_str, ip.src, ip.dst, length))
                if len(self.tree.get_children()) > MAX_PACKETS_DISPLAY:
                    self.tree.delete(self.tree.get_children()[-1])
        except:
            pass

    def apply_logic(self, df):
        """
        Centralized Logic Engine - Used for both Graphs and Excel
        """
        # AI Prediction
        if self.model:
            try:
                expected_cols = self.model.feature_names_in_
                for col in expected_cols:
                    if col not in df.columns: df[col] = 0
                X = df[expected_cols].fillna(0)
                predictions = self.model.predict(X)
                df['PREDICTED_CLASS'] = self.encoder.inverse_transform(predictions)
            except:
                df['PREDICTED_CLASS'] = "N/A"
        else:
            df['PREDICTED_CLASS'] = "N/A"

        # --- HYBRID LOGIC FIXES (The "Brain") ---
        current_time = time.time()
        total_bytes = df['fwd_bytes'] + df['bwd_bytes']

        # 1. Infrastructure (Stronger detection)
        # Added ports: 1900 (SSDP), 5353 (mDNS), 445 (SMB), 137 (NetBIOS)
        if 'dst_port' in df.columns:
            df.loc[df['dst_port'].isin([53, 123, 1900, 5353, 445, 137]), 'PREDICTED_CLASS'] = 'Infrastructure'

        # 2. Chat & Email (FIXED: TCP Only + Very Small)
        # זום הוא UDP, אז החוק הזה לא ייגע בו יותר!
        chat_mask = (total_bytes < 5000) & (df['protocol'] == 6)
        df.loc[chat_mask, 'PREDICTED_CLASS'] = 'Chat_and_Email'

        # 3. Streaming (Video)
        quic_streaming = (df['protocol'] == 17) & (df['dst_port'] == 443) & (total_bytes > 50000)
        df.loc[quic_streaming, 'PREDICTED_CLASS'] = 'Streaming'

        https_streaming = (df['protocol'] == 6) & (df['dst_port'] == 443) & (total_bytes > 2000000)
        df.loc[https_streaming, 'PREDICTED_CLASS'] = 'Streaming'

        # 4. File Transfer (Download)
        download_mask = (total_bytes > 1000000) & (df['fwd_iat_max'] < 0.5)
        df.loc[download_mask, 'PREDICTED_CLASS'] = 'File_Transfer'

        # 5. Real-Time Call (Zoom/Discord)
        # תופס כל UDP שהוא לא פורט 443 (יוטיוב) ויש לו נפח משמעותי
        rt_call = (total_bytes > 20000) & (df['protocol'] == 17) & (df['dst_port'] != 443)
        df.loc[rt_call, 'PREDICTED_CLASS'] = 'RealTime_Call'

        return df

    def update_graphs_loop(self):
        if not self.sniffing: return

        current_time = time.time()
        # Filter active flows
        active_flows = [f for f in self.flows.values() if current_time - f['last_seen'] < FLOW_TIMEOUT]

        if not active_flows:
            self.after(UPDATE_INTERVAL, self.update_graphs_loop)
            return

        df = pd.DataFrame(active_flows)
        df['duration'] = df['last_seen'] - df['start_time']

        # Apply the logic
        df = self.apply_logic(df)

        # Draw Graphs
        self.ax1.clear();
        self.ax2.clear()
        colors = ['#3498db', '#e74c3c', '#2ecc71', '#f1c40f', '#9b59b6', '#ecf0f1']

        # Volume Chart
        vol_data = df.groupby('PREDICTED_CLASS')['fwd_bytes'].sum()
        if vol_data.sum() > 0:
            wedges, texts, autotexts = self.ax1.pie(vol_data, labels=vol_data.index, autopct='%1.1f%%', colors=colors,
                                                    startangle=140)
            self.ax1.set_title("BANDWIDTH USAGE", color="white", fontsize=10)
            for t in texts: t.set_color("white"); t.set_fontsize(8)
            for at in autotexts: at.set_color("black"); at.set_fontsize(8)

        # Count Chart
        count_data = df['PREDICTED_CLASS'].value_counts()
        if count_data.sum() > 0:
            wedges, texts, autotexts = self.ax2.pie(count_data, labels=count_data.index, autopct='%1.1f%%',
                                                    colors=colors, startangle=140)
            self.ax2.set_title("ACTIVE CONNECTIONS", color="white", fontsize=10)
            for t in texts: t.set_color("white"); t.set_fontsize(8)
            for at in autotexts: at.set_color("black"); at.set_fontsize(8)

        self.ax1.set_facecolor('#2b2b2b')
        self.ax2.set_facecolor('#2b2b2b')

        self.canvas.draw()
        self.after(UPDATE_INTERVAL, self.update_graphs_loop)


if __name__ == "__main__":
    app = ModernNetWatch()
    app.mainloop()