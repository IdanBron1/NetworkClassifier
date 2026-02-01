import pandas as pd
from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP
import os


class FlowStats:
    def __init__(self, first_ts):
        self.start_time = first_ts
        self.end_time = first_ts
        self.fwd_pkts = 0
        self.fwd_bytes = 0
        self.bwd_pkts = 0
        self.bwd_bytes = 0
        self.fwd_last_ts = None
        self.bwd_last_ts = None
        self.fwd_iat_sum = 0.0
        self.bwd_iat_sum = 0.0
        self.fwd_iat_max = 0.0
        self.bwd_iat_max = 0.0
        self.fwd_syn = 0
        self.fwd_fin = 0
        self.bwd_syn = 0
        self.bwd_fin = 0

    def update_direction(self, direction, length, ts, flags=None):
        self.end_time = ts
        if direction == "fwd":
            self.fwd_pkts += 1
            self.fwd_bytes += length
            if self.fwd_last_ts is not None:
                iat = ts - self.fwd_last_ts
                self.fwd_iat_sum += iat
                if iat > self.fwd_iat_max: self.fwd_iat_max = iat
            self.fwd_last_ts = ts
            if flags:
                if "S" in flags: self.fwd_syn += 1
                if "F" in flags: self.fwd_fin += 1
        else:  # "bwd"
            self.bwd_pkts += 1
            self.bwd_bytes += length
            if self.bwd_last_ts is not None:
                iat = ts - self.bwd_last_ts
                self.bwd_iat_sum += iat
                if iat > self.bwd_iat_max: self.bwd_iat_max = iat
            self.bwd_last_ts = ts
            if flags:
                if "S" in flags: self.bwd_syn += 1
                if "F" in flags: self.bwd_fin += 1

    def to_dict(self, key):
        src, sport, dst, dport, proto = key
        duration = self.end_time - self.start_time if self.end_time >= self.start_time else 0.0
        fwd_iat_mean = self.fwd_iat_sum / max(self.fwd_pkts - 1, 1)
        bwd_iat_mean = self.bwd_iat_sum / max(self.bwd_pkts - 1, 1)
        return {
            "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport, "protocol": proto,
            "start_time": self.start_time, "end_time": self.end_time, "duration": duration,
            "fwd_pkts": self.fwd_pkts, "bwd_pkts": self.bwd_pkts,
            "fwd_bytes": self.fwd_bytes, "bwd_bytes": self.bwd_bytes,
            "fwd_iat_mean": fwd_iat_mean, "bwd_iat_mean": bwd_iat_mean,
            "fwd_iat_max": self.fwd_iat_max, "bwd_iat_max": self.bwd_iat_max,
            "fwd_syn": self.fwd_syn, "fwd_fin": self.fwd_fin,
            "bwd_syn": self.bwd_syn, "bwd_fin": self.bwd_fin,
        }


def get_5tuple(pkt):
    if not pkt.haslayer(IP): return None
    ip = pkt[IP]
    proto = ip.proto
    sport = 0
    dport = 0
    if pkt.haslayer(TCP):
        proto = 6
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = 17
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    return ip.src, sport, ip.dst, dport, proto


def get_tcp_flags(pkt):
    if pkt.haslayer(TCP): return pkt.sprintf("%TCP.flags%")
    return ""


def pcap_to_csv(input_pcap, output_csv):
    """
    Main function to convert a PCAP file to a CSV file.
    """
    print(f"--> Converting {os.path.basename(input_pcap)} to CSV...")
    flows = {}

    try:
        with PcapReader(input_pcap) as pcap_reader:
            for pkt in pcap_reader:
                try:
                    ts = float(pkt.time)
                    length = len(pkt)
                    five_tuple = get_5tuple(pkt)
                    if five_tuple is None: continue

                    src, sport, dst, dport, proto = five_tuple
                    key_fwd = (src, sport, dst, dport, proto)
                    key_bwd = (dst, dport, src, sport, proto)
                    flags = get_tcp_flags(pkt)

                    if key_fwd in flows:
                        flow = flows[key_fwd]
                        direction = "fwd"
                    elif key_bwd in flows:
                        flow = flows[key_bwd]
                        direction = "bwd"
                    else:
                        flow = FlowStats(ts)
                        flows[key_fwd] = flow
                        direction = "fwd"

                    flow.update_direction(direction, length, ts, flags)
                except Exception:
                    continue

        rows = [flow.to_dict(key) for key, flow in flows.items()]
        if not rows:
            print("No flows generated.")
            return False

        df = pd.DataFrame(rows)
        df.to_csv(output_csv, index=False)
        print(f"--> Conversion Success: {output_csv} (Rows: {len(df)})")
        return True

    except Exception as e:
        print(f"Error converting file: {e}")
        return False