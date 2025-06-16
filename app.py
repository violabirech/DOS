# dos_dashboard_no_time.py

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from influxdb_client import InfluxDBClient
import time

# --- InfluxDB Configuration ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_data"

# --- Page Setup ---
st.set_page_config(page_title="🛡️ DoS Attack Detection", layout="wide")

st.markdown("""
<style>
    .alert-high {background-color:#ffe6e6;border-left:5px solid red;padding:1rem;border-radius:8px;}
    .alert-medium {background-color:#fff8e6;border-left:5px solid orange;padding:1rem;border-radius:8px;}
    .alert-low {background-color:#e6ffe6;border-left:5px solid green;padding:1rem;border-radius:8px;}
</style>
""", unsafe_allow_html=True)

# --- Fetch Data ---
@st.cache_data(ttl=30)
def fetch_dos_data():
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        query_api = client.query_api()
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
        |> range(start: -1h)
        |> filter(fn: (r) => r["_measurement"] == "{MEASUREMENT}")
        |> pivot(rowKey:["_field"], columnKey: ["_field"], valueColumn: "_value")
        '''
        df = query_api.query_data_frame(query)
        client.close()
        return df
    except Exception as e:
        st.error(f"❌ Error: {e}")
        return pd.DataFrame()

# --- Detection Logic ---
def detect_dos(df):
    if df.empty:
        return {}

    syn_count = df[df['flags'] == 'SYN'].shape[0] if 'flags' in df else 0
    unique_ips = df['source_ip'].nunique() if 'source_ip' in df else 0
    large_packets = df[df['packet_size'] > 1000].shape[0] if 'packet_size' in df else 0
    total_packets = len(df)

    if total_packets > 3000 or syn_count > 1000:
        level = "HIGH"
        message = f"🚨 High traffic: {total_packets} packets, SYN={syn_count}"
    elif total_packets > 1000 or syn_count > 300:
        level = "MEDIUM"
        message = f"⚠️ Suspicious traffic: {total_packets} packets, SYN={syn_count}"
    else:
        level = "LOW"
        message = f"✅ Normal traffic: {total_packets} packets"

    return {
        "level": level,
        "message": message,
        "total_packets": total_packets,
        "syn_count": syn_count,
        "unique_ips": unique_ips,
        "large_packets": large_packets
    }

# --- Charts ---
def plot_top_ips(df):
    if 'source_ip' not in df:
        return go.Figure()
    top_ips = df['source_ip'].value_counts().head(10)
    fig = px.bar(x=top_ips.index, y=top_ips.values, title="Top Source IPs", labels={"x": "IP", "y": "Count"})
    fig.update_layout(xaxis_tickangle=-45)
    return fig

# --- Main ---
def main():
    st.title("🛡️ DoS Detection Dashboard (No Time Field)")

    auto_refresh = st.sidebar.checkbox("Auto Refresh (30s)", value=False)
    if st.sidebar.button("🔄 Manual Refresh") or auto_refresh:
        st.rerun()

    with st.spinner("Fetching data from InfluxDB..."):
        df = fetch_dos_data()

    if df.empty:
        st.warning("No DoS data found.")
        return

    alert = detect_dos(df)

    # Alert Box
    st.header("🚨 Alert Level")
    if alert['level'] == "HIGH":
        st.markdown(f"<div class='alert-high'>{alert['message']}</div>", unsafe_allow_html=True)
    elif alert['level'] == "MEDIUM":
        st.markdown(f"<div class='alert-medium'>{alert['message']}</div>", unsafe_allow_html=True)
    else:
        st.markdown(f"<div class='alert-low'>{alert['message']}</div>", unsafe_allow_html=True)

    # Metrics
    st.header("📊 DoS Metrics")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Packets", alert['total_packets'])
    col2.metric("SYN Packets", alert['syn_count'])
    col3.metric("Large Packets", alert['large_packets'])
    col4.metric("Unique IPs", alert['unique_ips'])

    # Visual
    st.header("📌 Top Offenders")
    st.plotly_chart(plot_top_ips(df), use_container_width=True)

    # Raw
    with st.expander("📋 Raw Data"):
        st.dataframe(df.tail(100))

    # Refresh
    if auto_refresh:
        time.sleep(30)
        st.rerun()

if __name__ == "__main__":
    main()
