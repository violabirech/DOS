import streamlit as st

# --- Page Setup - MUST BE FIRST STREAMLIT COMMAND ---
st.set_page_config(page_title="🚀 DoS Detection Dashboard", layout="wide")

# Now import everything else
import pandas as pd
import numpy as np
import requests
from datetime import datetime, timedelta
import time
from influxdb_client import InfluxDBClient
import plotly.express as px
import plotly.graph_objects as go
import warnings
warnings.filterwarnings('ignore')

# --- Configuration ---
PRIMARY_API_URL = "https://violabirech-dos-anomalies-detection.hf.space/predict"
BACKUP_API_URLS = [
    "https://violabirech-dos-anomalies-detection.hf.space/",
    "https://api-inference.huggingface.co/models/violabirech/dos-anomalies-detection"
]

INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
INFLUXDB_MEASUREMENT = "network_traffic"

# --- Initialize session state ---
if 'monitoring_active' not in st.session_state:
    st.session_state.monitoring_active = False
if 'historical_data' not in st.session_state:
    st.session_state.historical_data = []
if 'anomaly_alerts' not in st.session_state:
    st.session_state.anomaly_alerts = []
if 'query_performance' not in st.session_state:
    st.session_state.query_performance = []
if 'api_status' not in st.session_state:
    st.session_state.api_status = "Unknown"
if 'working_api_url' not in st.session_state:
    st.session_state.working_api_url = None

# --- Helper Functions ---
def mock_predict_anomaly(inter_arrival_time, packet_length):
    """Advanced mock API that simulates realistic DoS detection"""
    np.random.seed(int((inter_arrival_time * 1000 + packet_length) % 100))
    
    # Realistic DoS detection logic
    anomaly_score = 0
    
    # Check inter-arrival time (very fast requests are suspicious)
    if inter_arrival_time < 0.001:
        anomaly_score += 0.8
    elif inter_arrival_time < 0.01:
        anomaly_score += 0.4
    elif inter_arrival_time < 0.1:
        anomaly_score += 0.1
    
    # Check packet length (very large packets can indicate attacks)
    if packet_length > 1500:
        anomaly_score += 0.6
    elif packet_length > 1000:
        anomaly_score += 0.3
    elif packet_length < 64:
        anomaly_score += 0.2
    
    # Add some randomness
    anomaly_score += np.random.uniform(-0.1, 0.1)
    
    # Determine if it's an anomaly
    is_anomaly = 1 if anomaly_score > 0.5 else 0
    reconstruction_error = min(1.0, max(0.0, anomaly_score + np.random.uniform(-0.1, 0.1)))
    
    # Determine anomaly type
    if not is_anomaly:
        anomaly_type = "Normal_Traffic"
    elif inter_arrival_time < 0.001 and packet_length > 1000:
        anomaly_type = "DDoS_Flood_Attack"
    elif inter_arrival_time > 5.0 and packet_length < 300:
        anomaly_type = "Slowloris_Attack"
    elif packet_length > 1400:
        anomaly_type = "Amplification_Attack"
    else:
        anomaly_type = "Suspicious_Activity"
    
    return {
        "anomaly": is_anomaly,
        "reconstruction_error": reconstruction_error,
        "confidence": np.random.uniform(0.75, 0.95),
        "risk_score": min(1.0, anomaly_score),
        "anomaly_type": anomaly_type,
        "model_version": "mock_v2.1_realistic",
        "processing_time": np.random.uniform(0.05, 0.3),
        "timestamp": datetime.now().isoformat(),
        "features_used": ["inter_arrival_time", "packet_length"]
    }

def test_all_apis():
    """Test all possible API endpoints to find a working one"""
    test_payload = {
        "inter_arrival_time": 0.02,
        "packet_length": 5.0
    }
    
    all_urls = [PRIMARY_API_URL] + BACKUP_API_URLS
    
    for url in all_urls:
        try:
            response = requests.post(url, json=test_payload, timeout=5)
            if response.status_code == 200:
                result = response.json()
                return url
        except:
            continue
    
    return None

def predict_anomaly(inter_arrival_time, packet_length):
    """Enhanced prediction function with multiple fallback options"""
    if use_mock_api:
        return mock_predict_anomaly(inter_arrival_time, packet_length)
    
    payload = {
        "inter_arrival_time": float(inter_arrival_time),
        "packet_length": float(packet_length)
    }
    
    # Try working API first if we have one
    if st.session_state.working_api_url:
        try:
            response = requests.post(st.session_state.working_api_url, json=payload, timeout=10)
            if response.status_code == 200:
                result = response.json()
                st.session_state.api_status = "Online"
                return result
        except:
            st.session_state.working_api_url = None
    
    # Try all APIs
    all_urls = [PRIMARY_API_URL] + BACKUP_API_URLS
    
    for url in all_urls:
        try:
            response = requests.post(url, json=payload, timeout=5)
            if response.status_code == 200:
                result = response.json()
                st.session_state.api_status = "Online"
                st.session_state.working_api_url = url
                return result
        except:
            continue
    
    # All APIs failed, use mock
    st.session_state.api_status = "Offline"
    return mock_predict_anomaly(inter_arrival_time, packet_length)

@st.cache_data(ttl=60)
def get_influx_data_optimized(time_range, bucket, measurement, org, limit=50, timeout=15):
    """Optimized InfluxDB query with timeout and performance monitoring"""
    try:
        start_time = time.time()
        
        client = InfluxDBClient(
            url=INFLUXDB_URL, 
            token=INFLUXDB_TOKEN, 
            org=org, 
            timeout=timeout*1000
        )
        query_api = client.query_api()
        
        query = f'''
        from(bucket: "{bucket}")
          |> range(start: {time_range})
          |> filter(fn: (r) => r._measurement == "{measurement}")
          |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "packet_length" or r._field == "label")
          |> limit(n: {limit})
          |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
          |> sort(columns: ["_time"], desc: true)
        '''
        
        data = query_api.query_data_frame(org=org, query=query)
        
        if isinstance(data, list) and data:
            data = pd.concat(data, ignore_index=True)
        
        elapsed_time = time.time() - start_time
        
        perf_metric = {
            'timestamp': datetime.now(),
            'query_time': elapsed_time,
            'records_returned': len(data) if data is not None and not data.empty else 0,
            'time_range': time_range,
            'limit': limit
        }
        st.session_state.query_performance.append(perf_metric)
        
        if len(st.session_state.query_performance) > 50:
            st.session_state.query_performance = st.session_state.query_performance[-50:]
        
        client.close()
        return data, elapsed_time
        
    except Exception as e:
        error_time = time.time() - start_time if 'start_time' in locals() else 0
        st.error(f"InfluxDB Error (took {error_time:.2f}s): {e}")
        return None, error_time

def process_batch_predictions_optimized(df):
    """Optimized batch processing with progress indicators"""
    predictions = []
    
    if df.empty:
        return predictions
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    total_records = min(len(df), max_records)
    processed_df = df.head(total_records)
    
    for i, (index, row) in enumerate(processed_df.iterrows()):
        if not st.session_state.monitoring_active:
            break
            
        try:
            result = predict_anomaly(row['inter_arrival_time'], row['packet_length'])
            
            if 'error' not in result:
                result.update({
                    "timestamp": row["_time"],
                    "inter_arrival_time": row['inter_arrival_time'],
                    "packet_length": row['packet_length'],
                    "label": row.get("label", None),
                    "source_ip": row.get("source_ip", "Unknown"),
                    "dest_ip": row.get("dest_ip", "Unknown"),
                    "dns_rate": row.get("dns_rate", 1.0)
                })
                predictions.append(result)
                
                st.session_state.historical_data.append(result)
                
                if result.get('anomaly', 0) == 1:
                    alert = {
                        "timestamp": result["timestamp"],
                        "severity": "HIGH" if result.get('reconstruction_error', 0) > thresh * 2 else "MEDIUM",
                        "message": f"Anomaly detected: {result.get('anomaly_type', 'Unknown')} - Error: {result.get('reconstruction_error', 0):.4f}",
                        "source_ip": result.get("source_ip", "Unknown"),
                        "anomaly_type": result.get("anomaly_type", "Unknown")
                    }
                    st.session_state.anomaly_alerts.append(alert)
            
            progress = (i + 1) / total_records
            progress_bar.progress(progress)
            status_text.text(f"Processed {i + 1}/{total_records} records")
            
        except Exception as e:
            continue
    
    progress_bar.empty()
    status_text.empty()
    
    if len(st.session_state.historical_data) > 1000:
        st.session_state.historical_data = st.session_state.historical_data[-1000:]
    
    if len(st.session_state.anomaly_alerts) > 100:
        st.session_state.anomaly_alerts = st.session_state.anomaly_alerts[-100:]
    
    return predictions

def check_bucket_data(bucket, org, timeout=10):
    """Quick check if bucket contains any data"""
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=org, timeout=timeout*1000)
        query_api = client.query_api()
        
        basic_query = f'''
        from(bucket: "{bucket}")
          |> range(start: -24h)
          |> limit(n: 1)
        '''
        
        result = query_api.query_data_frame(org=org, query=basic_query)
        client.close()
        
        return result is not None and not result.empty
        
    except Exception as e:
        return False

def check_measurement_data(bucket, measurement, org, timeout=10):
    """Check if specific measurement exists"""
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=org, timeout=timeout*1000)
        query_api = client.query_api()
        
        measurement_query = f'''
        from(bucket: "{bucket}")
          |> range(start: -24h)
          |> filter(fn: (r) => r._measurement == "{measurement}")
          |> limit(n: 1)
        '''
        
        result = query_api.query_data_frame(org=org, query=measurement_query)
        client.close()
        
        return result is not None and not result.empty
        
    except Exception as e:
        return False

def run_diagnostic_query(query_name, query, org, timeout=10):
    """Run diagnostic query with error handling"""
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=org, timeout=timeout*1000)
        query_api = client.query_api()
        
        start_time = time.time()
        result = query_api.query_data_frame(org=org, query=query)
        elapsed = time.time() - start_time
        
        client.close()
        
        return {
            'success': True,
            'result': result,
            'elapsed': elapsed,
            'records': len(result) if result is not None and not result.empty else 0
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'elapsed': 0,
            'records': 0
        }

# --- Sidebar Controls ---
st.sidebar.title("🔧 Controls")

st.sidebar.markdown("---")
st.sidebar.subheader("🔌 API Configuration")
use_mock_api = st.sidebar.checkbox("Force Mock API (for testing)", value=False)

if st.sidebar.button("🔍 Test API Connection"):
    st.sidebar.write("Testing API...")
    working_url = test_all_apis()
    if working_url:
        st.sidebar.success(f"✅ Found working API")
        st.session_state.working_api_url = working_url
        st.session_state.api_status = "Online"
    else:
        st.sidebar.error("❌ No working APIs found")
        st.session_state.api_status = "Offline"

auto_refresh = st.sidebar.checkbox("Auto Refresh", value=False)
refresh_interval = st.sidebar.selectbox("Refresh Interval", [5, 10, 15, 30, 60], index=1)

time_window = st.sidebar.selectbox("Time Range", ["-5m", "-15m", "-1h", "-6h", "-12h", "-1d", "-7d", "-30d"], index=0)
thresh = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
max_records = st.sidebar.slider("Max Records to Process", 10, 100, 25, 10)

st.sidebar.markdown("---")
st.sidebar.subheader("⚡ Performance Settings")
query_timeout = st.sidebar.slider("Query Timeout (seconds)", 5, 60, 15, 5)
cache_ttl = st.sidebar.slider("Cache TTL (seconds)", 30, 300, 60, 30)

st.sidebar.markdown("---")
st.sidebar.subheader("🎛️ Monitoring Controls")

col1, col2 = st.sidebar.columns(2)
with col1:
    if st.button("▶️ Start", type="primary"):
        st.session_state.monitoring_active = True
with col2:
    if st.button("⏹️ Stop"):
        st.session_state.monitoring_active = False

if st.sidebar.button("🗑️ Clear History"):
    st.session_state.historical_data = []
    st.session_state.anomaly_alerts = []
    st.session_state.query_performance = []
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.subheader("🔧 Configuration Override")
custom_bucket = st.sidebar.text_input("Bucket Name", value=INFLUXDB_BUCKET)
custom_measurement = st.sidebar.text_input("Measurement Name", value=INFLUXDB_MEASUREMENT)
custom_org = st.sidebar.text_input("Organization", value=INFLUXDB_ORG)

if custom_bucket:
    INFLUXDB_BUCKET = custom_bucket
if custom_measurement:
    INFLUXDB_MEASUREMENT = custom_measurement
if custom_org:
    INFLUXDB_ORG = custom_org

# --- Title ---
st.title("🚀 Real-Time DoS Anomaly Detection Dashboard")

# Status indicator
status_col1, status_col2, status_col3, status_col4 = st.columns([1, 1, 1, 2])
with status_col1:
    if st.session_state.monitoring_active:
        st.success("🟢 ACTIVE")
    else:
        st.error("🔴 STOPPED")

with status_col2:
    st.info(f"⏱️ Refresh: {refresh_interval}s")

with status_col3:
    st.info(f"📊 Records: {max_records}")

with status_col4:
    if st.session_state.historical_data:
        last_update = max([d['timestamp'] for d in st.session_state.historical_data])
        st.write(f"📅 Last Update: {last_update}")

# API Status indicator
api_status_col1, api_status_col2, api_status_col3 = st.columns([1, 1, 2])
with api_status_col1:
    if st.session_state.api_status == "Online":
        st.success("🟢 API Online")
    elif st.session_state.api_status == "Offline":
        st.error("🔴 API Offline")
    else:
        st.warning("🟡 API Unknown")

with api_status_col2:
    if use_mock_api:
        st.info("🧪 Mock Mode")
    else:
        st.info("🔗 Live Mode")

with api_status_col3:
    if st.session_state.working_api_url:
        st.write(f"📡 Using: {st.session_state.working_api_url}")

# --- Navigation Tabs ---
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🏠 Overview", "📊 Live Stream", "⚙️ Manual Entry", "📈 Metrics & Alerts", "🔧 Diagnostics"])

# --- Tab 1: Overview ---
with tab1:
    st.subheader("📊 Analytical Dashboard")
    
    st.subheader("**System Status**")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.session_state.api_status == "Online":
            st.success("🟢 ML API: Online")
        elif st.session_state.api_status == "Offline":
            st.error("🔴 ML API: Offline")
        else:
            st.warning("🟡 ML API: Unknown")
    
    with col2:
        if use_mock_api:
            st.info("🧪 Mode: Mock API")
        else:
            st.info("🔗 Mode: Live API")
    
    with col3:
        st.info(f"🎯 Threshold: {thresh}")
    
    with col4:
        if st.session_state.working_api_url:
            st.success("✅ API Found")
        else:
            st.warning("⚠️ No API")
    
    if st.session_state.historical_data:
        st.subheader("**Detection Results**")
        df_hist = pd.DataFrame(st.session_state.historical_data)
        
        col1, col2, col3, col4 = st.columns(4)
        
        total_records = len(df_hist)
        anomaly_count = df_hist['anomaly'].sum() if 'anomaly' in df_hist.columns else 0
        normal_count = total_records - anomaly_count
        anomaly_rate = (anomaly_count / total_records * 100) if total_records > 0 else 0
        
        col1.metric("Total Records", total_records)
        col2.metric("Normal Traffic", normal_count)
        col3.metric("Anomalies Detected", anomaly_count)
        col4.metric("Anomaly Rate", f"{anomaly_rate:.1f}%")
        
        if total_records > 0:
            st.subheader("**Traffic Classification**")
            
            fig_pie = go.Figure(data=[go.Pie(
                labels=['Normal Traffic', 'Anomalous Traffic'],
                values=[normal_count, anomaly_count],
                hole=.3,
                marker_colors=['#2E8B57', '#DC143C']
            )])
            
            fig_pie.update_layout(
                title="Network Traffic Distribution",
                annotations=[dict(text=f'{anomaly_rate:.1f}%<br>Anomalies', x=0.5, y=0.5, font_size=16, showarrow=False)]
            )
            
            st.plotly_chart(fig_pie, use_container_width=True)
    
    else:
        st.info("📊 No data collected yet. Start monitoring to see analytics.")
        
        st.subheader("**Generate Sample Data for Testing**")
        if st.button("🎲 Generate Sample Detection Data", type="secondary"):
            sample_data = []
            for i in range(20):
                inter_arrival = np.random.exponential(0.05)
                packet_len = np.random.normal(800, 200)
                
                result = mock_predict_anomaly(inter_arrival, packet_len)
                result.update({
                    "timestamp": datetime.now() - timedelta(minutes=i),
                    "inter_arrival_time": inter_arrival,
                    "packet_length": packet_len,
                    "source_ip": f"192.168.1.{np.random.randint(1, 255)}",
                    "dest_ip": "192.168.1.1"
                })
                sample_data.append(result)
            
            st.session_state.historical_data.extend(sample_data)
            st.success("✅ Generated 20 sample detection records!")
            st.rerun()

# --- Tab 2: Live Stream ---
with tab2:
    st.subheader("📡 Real-Time Monitoring")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔍 Quick Data Check"):
            with st.spinner("Checking data availability..."):
                has_data = check_bucket_data(INFLUXDB_BUCKET, INFLUXDB_ORG)
                has_measurement = check_measurement_data(INFLUXDB_BUCKET, INFLUXDB_MEASUREMENT, INFLUXDB_ORG)
                
                if has_data:
                    st.success("✅ Bucket has data")
                else:
                    st.warning("⚠️ No data in bucket")
                
                if has_measurement:
                    st.success("✅ Measurement exists")
                else:
                    st.warning("⚠️ Measurement not found")
    
    with col2:
        if st.button("🔄 Manual Refresh"):
            st.rerun()
    
    if st.session_state.monitoring_active:
        st.info("🔄 Live monitoring active. Using mock data for demonstration.")
        
        if st.button("📊 Generate Live Data Sample"):
            sample_data = []
            for i in range(5):
                inter_arrival = np.random.exponential(0.02)
                packet_len = np.random.normal(800, 300)
                
                result = mock_predict_anomaly(inter_arrival, packet_len)
                result.update({
                    "timestamp": datetime.now(),
                    "inter_arrival_time": inter_arrival,
                    "packet_length": packet_len,
                    "source_ip": f"192.168.1.{np.random.randint(1, 255)}",
                    "dest_ip": "192.168.1.1"
                })
                sample_data.append(result)
            
            st.session_state.historical_data.extend(sample_data)
            
            df_pred = pd.DataFrame(sample_data)
            df_pred["timestamp"] = pd.to_datetime(df_pred["timestamp"])
            
            st.subheader("**Live Data Stream**")
            
            def highlight_anomalies(row):
                if row['anomaly'] == 1:
                    return ['background-color: #ffcccc'] * len(row)
                return [''] * len(row)
            
            display_df = df_pred[[
                "timestamp", "source_ip", "dest_ip", "inter_arrival_time", 
                "packet_length", "reconstruction_error", "anomaly", "anomaly_type"
            ]].copy()
            
            styled_df = display_df.style.apply(highlight_anomalies, axis=1)
            st.dataframe(styled_df, use_container_width=True, height=300)
            
            anomalies_in_batch = df_pred['anomaly'].sum()
            if anomalies_in_batch > 0:
                st.error(f"🚨 {anomalies_in_batch} anomalies detected in this batch!")
                
                anomaly_types = df_pred[df_pred['anomaly'] == 1]['anomaly_type'].value_counts()
                st.write("**Detected Attack Types:**")
                for attack_type, count in anomaly_types.items():
                    st.write(f"  • {attack_type}: {count}")
            else:
                st.success("✅ No anomalies detected in this batch")
    
    else:
        st.info("▶️ Click 'Start' in the sidebar to begin monitoring")
        
        # Manual mode data fetch - FIXED SECTION
        if st.button("📊 Fetch Data Now", type="primary"):
            with st.spinner("Fetching data..."):
                result = get_influx_data_optimized(
                    time_window,
                    INFLUXDB_BUCKET,
                    INFLUXDB_MEASUREMENT,
                    INFLUXDB_ORG,
                    max_records,
                    query_timeout
                )  # ✅ FIXED: Added missing closing parenthesis
                
                df, query_time = result if result else (None, 0)
                
                if df is not None and not df.empty:
                    st.success(f"✅ Retrieved {len(df)} records in {query_time:.2f}s")
                    st.dataframe(df.head(10))
                else:
                    st.warning(f"⚠️ No data found (query took {query_time:.2f}s)")

# --- Tab 3: Manual Entry ---
with tab3:
    st.subheader("🔧 Manual Entry for Testing")
    
    if st.session_state.api_status == "Offline":
        st.warning("⚠️ All APIs are offline. Using advanced mock predictions for testing.")
    elif use_mock_api:
        st.info("🧪 Mock API is enabled for testing purposes.")
    elif st.session_state
