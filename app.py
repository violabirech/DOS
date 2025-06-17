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
from influxdb_client.client.bucket_api import BucketsApi
import plotly.express as px
import plotly.graph_objects as go
import warnings
import os
warnings.filterwarnings('ignore')

# --- Configuration ---
# ✅ FIXED: Correct primary endpoint with authentication
PRIMARY_API_URL = "https://api-inference.huggingface.co/models/violabirech/dos-anomalies-detection"
BACKUP_API_URLS = [
    "https://violabirech-dos-anomalies-detection.hf.space/",
    "https://violabirech-dos-anomalies-detection.hf.space/call/predict",
    "https://violabirech-dos-anomalies-detection.hf.space/predict"
]

INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"

# --- ✅ ENHANCED SECURE TOKEN LOADING ---
INFLUXDB_TOKEN = None
HUGGINGFACE_API_TOKEN = None
INFLUXDB_AVAILABLE = False
HUGGINGFACE_API_AVAILABLE = False

# Load InfluxDB Token
try:
    INFLUXDB_TOKEN = st.secrets.get("INFLUXDB_TOKEN")
    if INFLUXDB_TOKEN:
        INFLUXDB_AVAILABLE = True
        st.sidebar.success("🔐 InfluxDB token loaded from secrets")
except:
    try:
        INFLUXDB_TOKEN = os.getenv("INFLUXDB_TOKEN")
        if INFLUXDB_TOKEN:
            INFLUXDB_AVAILABLE = True
            st.sidebar.success("🔐 InfluxDB token loaded from environment")
    except:
        pass

# Load Hugging Face API Token
try:
    HUGGINGFACE_API_TOKEN = st.secrets.get("HUGGINGFACE_API_TOKEN")
    if HUGGINGFACE_API_TOKEN:
        HUGGINGFACE_API_AVAILABLE = True
        st.sidebar.success("🔐 HF API token loaded from secrets")
except:
    try:
        HUGGINGFACE_API_TOKEN = os.getenv("HUGGINGFACE_API_TOKEN")
        if HUGGINGFACE_API_TOKEN:
            HUGGINGFACE_API_AVAILABLE = True
            st.sidebar.success("🔐 HF API token loaded from environment")
    except:
        pass

# Manual token input fallback
if not INFLUXDB_AVAILABLE or not HUGGINGFACE_API_AVAILABLE:
    st.sidebar.markdown("---")
    st.sidebar.subheader("🔑 Manual Token Input")
    
    if not INFLUXDB_AVAILABLE:
        manual_influx_token = st.sidebar.text_input(
            "InfluxDB Token (optional)", 
            type="password",
            help="Enter your InfluxDB token to enable database features"
        )
        if manual_influx_token:
            INFLUXDB_TOKEN = manual_influx_token
            INFLUXDB_AVAILABLE = True
            st.sidebar.success("🔐 Using manual InfluxDB token")

    if not HUGGINGFACE_API_AVAILABLE:
        manual_hf_token = st.sidebar.text_input(
            "Hugging Face API Token (required for live API)", 
            type="password",
            help="Get your token from https://huggingface.co/settings/tokens"
        )
        if manual_hf_token:
            HUGGINGFACE_API_TOKEN = manual_hf_token
            HUGGINGFACE_API_AVAILABLE = True
            st.sidebar.success("🔐 Using manual HF token")

# Status indicators
if not INFLUXDB_AVAILABLE:
    st.sidebar.warning("⚠️ InfluxDB features disabled (no token)")
if not HUGGINGFACE_API_AVAILABLE:
    st.sidebar.warning("⚠️ Live API disabled (no HF token)")

INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
INFLUXDB_MEASUREMENT = "network_traffic"

# --- Initialize session state ---
session_defaults = {
    'monitoring_active': False,
    'historical_data': [],
    'anomaly_alerts': [],
    'query_performance': [],
    'api_status': "Unknown",
    'working_api_url': None
}

for key, default_value in session_defaults.items():
    if key not in st.session_state:
        st.session_state[key] = default_value

# --- Helper Functions ---
def mock_predict_anomaly(inter_arrival_time, packet_length):
    """Advanced mock API that simulates realistic DoS detection"""
    np.random.seed(int((inter_arrival_time * 1000 + packet_length) % 100))
    
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
    
    anomaly_score += np.random.uniform(-0.1, 0.1)
    
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

def test_huggingface_inference_api(test_payload):
    """Test Hugging Face Inference API with proper authentication"""
    if not HUGGINGFACE_API_AVAILABLE:
        st.error("❌ Hugging Face API token not available")
        return None
    
    headers = {"Authorization": f"Bearer {HUGGINGFACE_API_TOKEN}"}
    
    try:
        st.write(f"🔍 Testing Hugging Face Inference API: {PRIMARY_API_URL}")
        
        # HF Inference API expects different payload format
        hf_payload = {
            "inputs": [test_payload["inter_arrival_time"], test_payload["packet_length"]]
        }
        
        response = requests.post(PRIMARY_API_URL, json=hf_payload, headers=headers, timeout=15)
        
        if response.status_code == 200:
            try:
                result = response.json()
                st.success(f"✅ Hugging Face Inference API working!")
                st.json(result)
                return PRIMARY_API_URL
            except ValueError:
                st.error("❌ Invalid JSON response from HF API")
        elif response.status_code == 503:
            st.warning("⚠️ Model is loading, please wait and try again...")
        else:
            st.error(f"❌ HF API returned status {response.status_code}: {response.text[:200]}...")
            
    except requests.exceptions.Timeout:
        st.error("❌ HF API request timed out")
    except Exception as e:
        st.error(f"❌ HF API error: {str(e)}")
    
    return None

def test_gradio_space_patterns(base_url, test_payload):
    """Test different Gradio Space API patterns"""
    patterns = [
        {"url": base_url, "data": {"data": [test_payload["inter_arrival_time"], test_payload["packet_length"]]}},
        {"url": f"{base_url}call/predict", "data": {"data": [test_payload["inter_arrival_time"], test_payload["packet_length"]]}},
        {"url": f"{base_url}predict", "data": test_payload},
        {"url": base_url, "data": test_payload}
    ]
    
    for pattern in patterns:
        try:
            st.write(f"🔍 Testing Gradio pattern: {pattern['url']}")
            
            response = requests.post(pattern["url"], json=pattern["data"], timeout=10)
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    
                    # Check different response formats
                    if isinstance(result, dict) and "data" in result:
                        st.success(f"✅ Gradio Space API working: {pattern['url']}")
                        st.json(result)
                        return pattern['url']
                    elif isinstance(result, list):
                        st.success(f"✅ Gradio Space API working: {pattern['url']}")
                        st.json(result)
                        return pattern['url']
                    
                except ValueError:
                    st.error(f"❌ Invalid JSON from {pattern['url']}")
            else:
                st.write(f"Status {response.status_code}: {response.text[:100]}...")
                
        except Exception as e:
            st.write(f"Error: {str(e)}")
    
    return None

def test_all_apis():
    """Enhanced API testing with proper authentication and multiple patterns"""
    test_payload = {
        "inter_arrival_time": 0.02,
        "packet_length": 800.0
    }
    
    st.write("🔍 **Testing APIs in order of preference...**")
    
    # 1. Test Hugging Face Inference API first (most reliable)
    working_url = test_huggingface_inference_api(test_payload)
    if working_url:
        return working_url
    
    # 2. Test Gradio Space patterns
    st.write("🔍 **Testing Gradio Space patterns...**")
    base_url = "https://violabirech-dos-anomalies-detection.hf.space/"
    working_url = test_gradio_space_patterns(base_url, test_payload)
    if working_url:
        return working_url
    
    st.error("❌ No working APIs found. Using mock mode.")
    return None

def predict_anomaly(inter_arrival_time, packet_length):
    """Enhanced prediction function with proper authentication"""
    if use_mock_api:
        return mock_predict_anomaly(inter_arrival_time, packet_length)
    
    payload = {
        "inter_arrival_time": float(inter_arrival_time),
        "packet_length": float(packet_length)
    }
    
    # Try working API first if we have one
    if st.session_state.working_api_url:
        try:
            if st.session_state.working_api_url == PRIMARY_API_URL and HUGGINGFACE_API_AVAILABLE:
                # Use HF Inference API format
                headers = {"Authorization": f"Bearer {HUGGINGFACE_API_TOKEN}"}
                hf_payload = {"inputs": [float(inter_arrival_time), float(packet_length)]}
                
                response = requests.post(st.session_state.working_api_url, json=hf_payload, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Convert HF response to standard format
                    if isinstance(result, list) and len(result) >= 2:
                        converted_result = {
                            "anomaly": int(result[0]),
                            "reconstruction_error": float(result[1]),
                            "confidence": float(result[2]) if len(result) > 2 else 0.8,
                            "anomaly_type": str(result[3]) if len(result) > 3 else "Unknown",
                            "model_version": "huggingface_inference_v1.0",
                            "timestamp": datetime.now().isoformat()
                        }
                        st.session_state.api_status = "Online"
                        return converted_result
            else:
                # Use standard format for Gradio endpoints
                response = requests.post(st.session_state.working_api_url, json=payload, timeout=10)
                
                if response.status_code == 200:
                    result = response.json()
                    st.session_state.api_status = "Online"
                    return result
                    
        except Exception as e:
            st.session_state.working_api_url = None
    
    # All APIs failed, use mock
    st.session_state.api_status = "Offline"
    return mock_predict_anomaly(inter_arrival_time, packet_length)

def generate_realistic_mock_data(num_records=50):
    """Generate realistic network traffic data for testing"""
    data = []
    base_time = datetime.now()
    
    for i in range(num_records):
        if np.random.random() < 0.15:  # 15% anomalous traffic
            attack_type = np.random.choice(['ddos', 'slowloris', 'amplification'])
            
            if attack_type == 'ddos':
                inter_arrival = np.random.exponential(0.0005)
                packet_length = np.random.choice([1200, 1400, 1500])
            elif attack_type == 'slowloris':
                inter_arrival = np.random.uniform(3.0, 8.0)
                packet_length = np.random.uniform(100, 300)
            else:  # amplification
                inter_arrival = np.random.exponential(0.01)
                packet_length = np.random.uniform(1400, 1500)
            
            label = 1
        else:
            # Normal traffic
            inter_arrival = np.random.exponential(0.05)
            packet_length = np.random.normal(800, 200)
            packet_length = max(64, min(1500, packet_length))
            label = 0
        
        record = {
            '_time': base_time - timedelta(seconds=i * 0.1),
            'inter_arrival_time': inter_arrival,
            'packet_length': packet_length,
            'label': label,
            'source_ip': f"192.168.{np.random.randint(1, 10)}.{np.random.randint(1, 255)}",
            'dest_ip': f"10.0.0.{np.random.randint(1, 10)}",
            'dns_rate': np.random.uniform(0.5, 3.0)
        }
        data.append(record)
    
    return pd.DataFrame(data)

@st.cache_data(ttl=60)
def get_influx_data_optimized(time_range, bucket, measurement, org, limit=50, timeout=15):
    """Enhanced InfluxDB query with fallback to mock data"""
    if not INFLUXDB_AVAILABLE:
        st.info("🧪 Using mock data - InfluxDB not available")
        return generate_realistic_mock_data(limit), 0.1
    
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
        client.close()
        
        if data is not None and not data.empty:
            st.success(f"✅ Retrieved {len(data)} records from InfluxDB")
            return data, elapsed_time
        else:
            st.warning("⚠️ InfluxDB query returned no data. Using mock data.")
            return generate_realistic_mock_data(limit), elapsed_time
        
    except Exception as e:
        error_time = time.time() - start_time if 'start_time' in locals() else 0
        
        if "could not find bucket" in str(e):
            st.error(f"❌ Bucket '{bucket}' not found. Using mock data.")
        else:
            st.error(f"❌ InfluxDB Error: {e}")
        
        st.info("🔄 Automatically switching to mock data for demonstration.")
        return generate_realistic_mock_data(limit), error_time

def check_bucket_data(bucket, org, timeout=10):
    """Quick check if bucket contains any data"""
    if not INFLUXDB_AVAILABLE:
        return False
    
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
        timestamps = [pd.to_datetime(d['timestamp']) for d in st.session_state.historical_data if 'timestamp' in d]
        if timestamps:
            last_update = max(timestamps).strftime("%Y-%m-%d %H:%M:%S")
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
    
    if st.session_state.historical_data:
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
            
            # Time series visualization
            if 'timestamp' in df_hist.columns:
                st.subheader("**Anomaly Detection Timeline**")
                df_hist['timestamp'] = pd.to_datetime(df_hist['timestamp'])
                
                fig_timeline = px.scatter(
                    df_hist, 
                    x='timestamp', 
                    y='reconstruction
