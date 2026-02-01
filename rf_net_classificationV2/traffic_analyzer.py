import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import os

def analyze_traffic(csv_path, model_path, encoder_path):
    """
    Analyzes the CSV traffic using AI + Behavioral Logic.
    """
    print(f"--> Starting Analysis on {os.path.basename(csv_path)}...")

    # Check if model files exist
    if not os.path.exists(model_path) or not os.path.exists(encoder_path):
        print("Error: Model files (.pkl) not found!")
        return

    try:
        rf_model = joblib.load(model_path)
        label_encoder = joblib.load(encoder_path)

        new_df = pd.read_csv(csv_path)

        # Take all traffic (Packets > 0)
        heavy_traffic = new_df[new_df['fwd_pkts'] > 0].copy()

        if heavy_traffic.empty:
            print("No traffic to analyze.")
            return

        # Prepare for Model
        cols_to_drop_model = ["src_ip", "dst_ip", "src_port", "dst_port", "start_time", "end_time", "source_label", "filename"]
        model_features = heavy_traffic.drop(columns=cols_to_drop_model, errors='ignore').fillna(0)

        # 1. AI Prediction
        predictions = rf_model.predict(model_features)
        heavy_traffic['PREDICTED_CLASS'] = label_encoder.inverse_transform(predictions)

        # ==========================================
        # 2. Hybrid Logic Engine
        # ==========================================

        # A. Infrastructure Trap (DNS/NTP)
        if 'dst_port' in heavy_traffic.columns:
            heavy_traffic.loc[heavy_traffic['dst_port'] == 53, 'PREDICTED_CLASS'] = 'DNS_Infrastructure'
            heavy_traffic.loc[heavy_traffic['dst_port'] == 123, 'PREDICTED_CLASS'] = 'NTP_Infrastructure'

        # B. Mouse Rule (UPDATED: Lower threshold to 2KB)
        # הורדנו ל-2000 כדי ששיחות קוליות קצרות (כמו דיסקורד) לא ייחשבו כצ'אט.
        mouse_mask = (heavy_traffic['fwd_bytes'] < 2000) & (~heavy_traffic['PREDICTED_CLASS'].str.contains('Infrastructure', na=False))
        heavy_traffic.loc[mouse_mask, 'PREDICTED_CLASS'] = 'Chat_and_Email'

        # C. Streaming Logic (Behavioral)
        medium_flow_mask = heavy_traffic['fwd_bytes'] > 500000
        is_udp = heavy_traffic['protocol'] == 17
        has_buffering = heavy_traffic['fwd_iat_max'] > 1.5

        youtube_rule = (medium_flow_mask) & (is_udp) & (has_buffering)
        if youtube_rule.sum() > 0:
            print(f"  -> Detected {youtube_rule.sum()} flows as Streaming (Behavioral Fix).")
            heavy_traffic.loc[youtube_rule, 'PREDICTED_CLASS'] = 'Streaming'

        # D. False File Transfer Correction
        quic_fix = (heavy_traffic['PREDICTED_CLASS'] == 'File_Transfer') & (heavy_traffic['protocol'] == 17)
        if quic_fix.sum() > 0:
            print(f"  -> Corrected {quic_fix.sum()} QUIC flows to Streaming.")
            heavy_traffic.loc[quic_fix, 'PREDICTED_CLASS'] = 'Streaming'

        buffering_fix = (heavy_traffic['PREDICTED_CLASS'] == 'File_Transfer') & (heavy_traffic['fwd_iat_max'] > 1.0)
        if buffering_fix.sum() > 0:
            print(f"  -> Corrected {buffering_fix.sum()} buffering flows to Streaming.")
            heavy_traffic.loc[buffering_fix, 'PREDICTED_CLASS'] = 'Streaming'

        # 3. Visualization
        fig, axes = plt.subplots(1, 2, figsize=(14, 7))
        colors = sns.color_palette('pastel')

        # Graph 1: Volume
        vol_data = heavy_traffic.groupby('PREDICTED_CLASS')['fwd_bytes'].sum()
        if vol_data.sum() > 0:
            axes[0].pie(vol_data, labels=vol_data.index, autopct='%1.1f%%', colors=colors)
            axes[0].set_title("Bandwidth Volume")
        else:
            axes[0].text(0.5, 0.5, "No Data", ha='center')

        # Graph 2: Count
        count_data = heavy_traffic['PREDICTED_CLASS'].value_counts()
        if count_data.sum() > 0:
            axes[1].pie(count_data, labels=count_data.index, autopct='%1.1f%%', colors=colors)
            axes[1].set_title("Connection Count")
        else:
            axes[1].text(0.5, 0.5, "No Data", ha='center')

        plt.suptitle(f"Analysis Report: {os.path.basename(csv_path)}", fontsize=16)
        plt.tight_layout()
        plt.show()

    except Exception as e:
        print(f"Analysis Error: {e}")