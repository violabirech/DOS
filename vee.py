import streamlit as st
import numpy as np
import pandas as pd
from influxdb_client import InfluxDBClient
from sklearn.ensemble import IsolationForest
import plotly.express as px

# --- InfluxDB Configuration ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "your_token_here"
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_traffic"

# --- Page Setup ---
st.set_page_config(page_title="🚨 DoS Detection", layout="wide")
st.title("🚨 Real-Time DoS Anomaly Detection")

# --- Sidebar Controls ---
st.sidebar.header("Controls")
use_live = st.sidebar.checkbox("📡 Use Live InfluxDB Data", value=False)
inter_arrival = st.sidebar.number_input("🕒 Inter-Arrival Time (s)", min_value=0.0001, value=0.05)
packet_length = st.sidebar.number_input("📦 Packet Length (bytes)", min_value=1, value=500)
unique_ips = st.sidebar.number_input("🌐 Unique Source IPs", min_value=1, value=30)
anomaly_threshold = st.sidebar.slider("Anomaly Score Threshold", -0.5, 0.5, 0.0, 0.01)

# --- Train Model ---
@st.cache_resource
def train_model():
    normal = pd.DataFrame({
        "packet_rate": np.random.normal(50, 10, 300),
        "packet_length": np.random.normal(500, 50, 300),
        "inter_arrival_time": np.random.normal(0.05, 0.01, 300),
        "unique_ips": np.random.poisson(30, 300)
    })
    anomalies = pd.DataFrame({
        "packet_rate": np.random.uniform(800, 1500, 20),
        "packet_length": np.random.uniform(1000, 2000, 20),
        "inter_arrival_time": np.random.uniform(0.0001, 0.01, 20),
        "unique_ips": np.random.randint(500, 1000, 20)
    })
    df = pd.concat([normal, anomalies])
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(df)
    return model

model = train_model()

# --- Fetch Live Data ---
@st.cache_data(ttl=60)
def fetch_data():
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        query_api = client.query_api()
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
        |> range(start: -1000h)
        |> filter(fn: (r) => r._measurement == "{MEASUREMENT}")
        |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
        '''
        df = query_api.query_data_frame(query)
        client.close()
        return df
    except Exception as e:
        st.error(f"❌ Error fetching data: {e}")
        return pd.DataFrame()

# --- Use Live or Manual Data ---
if use_live:
    st.subheader("📡 Using Live Data from InfluxDB")
    df = fetch_data()
    if df.empty:
        st.warning("⚠️ No live data found.")
        st.stop()
    inter_arrival = df["inter_arrival_time"].replace(0, np.nan).mean()
    packet_length = df["packet_length"].mean()
    unique_ips = df["source_ip"].nunique()
    packet_rate = 1 / inter_arrival if inter_arrival and inter_arrival > 0 else 0
    st.success("✅ Live data loaded.")
    with st.expander("🧾 Raw Data Sample"):
        st.dataframe(df.tail(10))
else:
    st.subheader("🛠 Using Manual Input")
    packet_rate = 1 / inter_arrival if inter_arrival > 0 else 0

# --- Inference ---
features = np.array([[packet_rate, packet_length, inter_arrival, unique_ips]])
prediction = model.predict(features)[0]
score = model.decision_function(features)[0]

st.subheader("🔎 Anomaly Detection Result")
st.metric("Anomaly Score", f"{score:.4f}")
if prediction == -1 or score < anomaly_threshold:
    st.error("🚨 Anomaly Detected: Possible DoS Attack")
else:
    st.success("✅ Normal Traffic Behavior")

# --- Feature Metrics ---
st.subheader("📊 Feature Breakdown")
col1, col2, col3, col4 = st.columns(4)
col1.metric("Packet Rate", f"{packet_rate:.2f} pkts/s")
col2.metric("Packet Length", f"{packet_length:.0f} bytes")
col3.metric("Inter-Arrival Time", f"{inter_arrival:.4f} s")
col4.metric("Unique IPs", f"{unique_ips:,}")

# --- Visualizations ---
if use_live and not df.empty:
    df["timestamp"] = pd.to_datetime(df["_time"])
    df["packet_rate"] = 1 / df["inter_arrival_time"].replace(0, np.nan)

    with st.expander("📈 Packet Rate Over Time"):
        fig = px.line(df.tail(100), x="timestamp", y="packet_rate",
                      title="📈 Packet Rate Over Time (Last 100 Records)",
                      labels={"packet_rate": "Packets per Second"})
        st.plotly_chart(fig, use_container_width=True)

    with st.expander("🧭 Anomaly Scatter Plot"):
        df["anomaly"] = model.predict(df[["packet_rate", "packet_length", "inter_arrival_time", "unique_ips"]].fillna(0))
        fig2 = px.scatter(df.tail(200),
                          x="packet_rate",
                          y="packet_length",
                          color=df["anomaly"].map({1: "Normal", -1: "Anomaly"}),
                          title="Packet Rate vs Packet Length - Anomaly Detection",
                          labels={"packet_rate": "Packet Rate", "packet_length": "Packet Length"})
        st.plotly_chart(fig2, use_container_width=True)

# --- Model Info ---
with st.expander("ℹ️ Model Info"):
    st.markdown("""
- **Model**: Isolation Forest
- **Features Used**:
    - Packet Rate = 1 / Inter-Arrival Time
    - Packet Length (bytes)
    - Unique IPs
    - Inter-Arrival Time (s)
- **Trained On**: Simulated Normal & DoS Traffic
""")
