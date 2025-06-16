import streamlit as st
import numpy as np
import pandas as pd
from influxdb_client import InfluxDBClient
from sklearn.ensemble import IsolationForest

# --- InfluxDB Configuration ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_traffic"

# --- Page Setup ---
st.set_page_config(page_title="🛡️ DoS Anomaly Detection", layout="wide")
st.title("🛡️ Real-Time DoS Detection Dashboard")
st.markdown("Detect anomalies using InfluxDB features: packet length, arrival time, and source IP diversity.")

# --- Manual Input Section ---
st.sidebar.header("Manual Input or Live Mode")
inter_arrival = st.sidebar.number_input("Inter-Arrival Time (s)", min_value=0.00001, value=0.05)
packet_length = st.sidebar.number_input("Avg Packet Length (bytes)", min_value=1, value=500)
unique_ips = st.sidebar.number_input("Unique Source IPs", min_value=1, value=30)
use_live = st.sidebar.checkbox("📡 Use Live InfluxDB Data", value=True)

# --- Fetch InfluxDB Data ---
@st.cache_data(ttl=30)
def fetch_live_data():
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        query_api = client.query_api()
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
        |> range(start: -1100h)
        |> filter(fn: (r) => r["_measurement"] == "{MEASUREMENT}")
        |> keep(columns: ["inter_arrival_time", "packet_length", "source_ip"])
        '''
        df = query_api.query_data_frame(query)
        client.close()
        return df
    except Exception as e:
        st.error(f"❌ InfluxDB Error: {e}")
        return pd.DataFrame()

# --- Train Isolation Forest Model ---
@st.cache_resource
def train_model():
    normal = pd.DataFrame({
        "packet_rate": np.random.normal(50, 10, 300),
        "avg_packet_size": np.random.normal(500, 100, 300),
        "unique_ips": np.random.poisson(20, 300)
    })
    anomalies = pd.DataFrame({
        "packet_rate": np.random.uniform(1000, 2000, 20),
        "avg_packet_size": np.random.uniform(1000, 2000, 20),
        "unique_ips": np.random.randint(500, 1000, 20)
    })
    combined = pd.concat([normal, anomalies])
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(combined)
    return model

model = train_model()

# --- Use Live Data or Manual ---
if use_live:
    st.subheader("📡 Live Traffic Data from InfluxDB")
    df = fetch_live_data()

    if df.empty:
        st.warning("⚠️ No live data found.")
        st.stop()

    with st.expander("🔍 View Raw Data"):
        st.dataframe(df.tail(50))

    # Compute model inputs
    mean_arrival = df["inter_arrival_time"].replace(0, np.nan).mean()
    packet_length = df["packet_length"].mean()
    unique_ips = df["source_ip"].nunique()
    packet_rate = 1 / mean_arrival if mean_arrival and mean_arrival > 0 else 0

else:
    packet_rate = 1 / inter_arrival if inter_arrival > 0 else 0

# --- Inference ---
X = np.array([[packet_rate, packet_length, unique_ips]])
prediction = model.predict(X)[0]
score = model.decision_function(X)[0]

# --- Output ---
st.subheader("🔍 Anomaly Detection Result")
st.metric("Anomaly Score", f"{score:.4f}")
if prediction == -1:
    st.error("🚨 Anomaly Detected: Possible DoS Attack")
else:
    st.success("✅ Normal Behavior")

# --- Feature Summary ---
st.markdown("### 📊 Feature Breakdown")
col1, col2, col3 = st.columns(3)
col1.metric("Packet Rate", f"{packet_rate:.2f} pkt/s")
col2.metric("Packet Size", f"{packet_length:.1f} bytes")
col3.metric("Unique IPs", unique_ips)

# --- Explain ---
with st.expander("ℹ️ Model Info"):
    st.markdown("""
    - **packet_rate** = 1 / average inter-arrival time
    - **packet_length** = mean bytes from `packet_length`
    - **unique_ips** = distinct values of `source_ip`
    - Model: Isolation Forest trained on synthetic normal & abnormal traffic
    """)
