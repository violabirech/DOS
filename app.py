# dos_dashboard.py

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from influxdb_client import InfluxDBClient
from datetime import datetime, timedelta
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
def fetch_dos_data(time_range="1h"):
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        query_api = client.query_api()
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
        |> range(start: -{time_range})
        |> filter(fn: (r) => r["_measurement"] == "{MEASUREMENT}")
        |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
        |> sort(columns: ["_time"])
        '''
        df = query_api.query_data_frame(query)
        client.close()
        df['_time'] = pd.to_datetime(df['_time'])
        return df
    except Exception as e:
        st.error(f"❌ Error: {e}")
        return pd.DataFrame()

# --- Detection Logic ---
def detect_dos(df):
    if df.empty:
        return {}

    now = datetime.now()
    last_minute = df[df['_time'] >= now - timedelta(minutes=1)]

    alert = {}
    pps = len(last_minute)
    syn_count = df[df['flags'] == 'SYN'].shape[0] if 'flags' in df else 0
    unique_ips = df['source_ip'].nunique() if 'source_ip' in df else 0
    large_packets = df[df['packet_size'] > 1000].shape[0] if 'packet_size' in df else 0

    if pps > 3000 or syn_count > 1000:
        alert['level'] = "HIGH"
        alert['message'] = f"🚨 High DoS activity: {pps} packets/min, SYN={syn_count}"
    elif pps > 1000 or syn_count > 300:
        alert['level'] = "MEDIUM"
        alert['message'] = f"⚠️ Suspicious DoS traffic: {pps} packets/min, SYN={syn_count}"
    else:
        alert['level'] = "LOW"
        alert['message'] = f"✅ Normal traffic: {pps} packets/min"

    alert.update({
        "pps": pps,
        "syn_count": syn_count,
        "unique_ips": unique_ips,
        "large_packets": large_packets
    })
    return alert

# --- Charts ---
def plot_packets_over_time(df):
    df_resampled = df.set_index('_time').resample('1T').size().reset_index()
    df_resampled.columns = ['time', 'packets']
    fig = px.line(df_resampled, x='time', y='packets', title='📈 Packets per Minute (DoS Traffic)')
    fig.update_layout(hovermode='x unified')
    return fig

def plot_top_ips(df):
    if 'source_ip' not in df:
        return go.Figure()
    top_ips = df['source_ip'].value_counts().head(10)
    fig = px.bar(x=top_ips.index, y=top_ips.values, title="Top Source IPs", labels={"x": "IP", "y": "Count"})
    fig.update_layout(xaxis_tickangle=-45)
    return fig

# --- Main ---
def main():
    st.title("🛡️ Real-Time DoS Detection Dashboard")

    time_range = st.sidebar.selectbox("Time Range", ["5m", "15m", "1h", "6h"], index=2)
    auto_refresh = st.sidebar.checkbox("Auto Refresh (30s)", value=False)

    if st.sidebar.button("🔄 Manual Refresh") or auto_refresh:
        st.rerun()

    with st.spinner("Fetching data from InfluxDB..."):
        df = fetch_dos_data(time_range)

    if df.empty:
        st.warning("No DoS data found in InfluxDB.")
        st.info("Ensure InfluxDB contains the 'network_data' measurement with fields like source_ip, flags, packet_size.")
        return

    alert = detect_dos(df)

    # --- Alert Box ---
    st.header("🚨 DoS Alerts")
    if alert['level'] == "HIGH":
        st.markdown(f"<div class='alert-high'>{alert['message']}</div>", unsafe_allow_html=True)
    elif alert['level'] == "MEDIUM":
        st.markdown(f"<div class='alert-medium'>{alert['message']}</div>", unsafe_allow_html=True)
    else:
        st.markdown(f"<div class='alert-low'>{alert['message']}</div>", unsafe_allow_html=True)

    # --- Metrics ---
    st.header("📊 Traffic Metrics")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Packets/min", alert['pps'])
    col2.metric("SYN Count", alert['syn_count'])
    col3.metric("Large Packets", alert['large_packets'])
    col4.metric("Unique IPs", alert['unique_ips'])

    # --- Visualizations ---
    st.plotly_chart(plot_packets_over_time(df), use_container_width=True)
    st.plotly_chart(plot_top_ips(df), use_container_width=True)

    # --- Raw Data ---
    with st.expander("📋 Raw DoS Traffic Data"):
        st.dataframe(df.tail(100))

if __name__ == "__main__":
    main()
