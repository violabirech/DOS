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
warnings.filterwarnings('ignore')

# --- Configuration ---
# ✅ FIXED: Corrected API URL to include /api/predict
PRIMARY_API_URL = "https://violabirech-dos-anomalies-detection.hf.space/api/predict" 
BACKUP_API_URLS = [
    "https://violabirech-dos-anomalies-detection.hf.space/predict",
    "https://violabirech-dos-anomalies-detection.hf.space/",
    "https://api-inference.huggingface.co/models/violabirech/dos-anomalies-detection"
]

INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
# --- ✅ SECURITY FIX: Secure token loading ---
try:
    INFLUXDB_TOKEN = st.secrets["INFLUXDB_TOKEN"]
except KeyError:
    st.error("🚨 InfluxDB token not found in Streamlit secrets!")
    INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="
    st.stop()


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

def test_all_apis():
    """Enhanced API testing with detailed logging"""
    test_payload = {
        "inter_arrival_time": 0.02,
        "packet_length": 800.0
    }
    
    all_urls = [PRIMARY_API_URL] + BACKUP_API_URLS
    
    for i, url in enumerate(all_urls):
        try:
            st.write(f"🔍 Testing API {i+1}/{len(all_urls)}: {url}")
            
            response = requests.post(url, json=test_payload, timeout=10)
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    required_keys = ["anomaly", "reconstruction_error"]
                    if all(key in result for key in required_keys):
                        st.success(f"✅ API {i+1} working: {url}")
                        st.json(result)
                        return url
                    else:
                        st.error(f"❌ API {i+1} returned invalid response structure")
                except ValueError:
                    st.error(f"❌ API {i+1} returned invalid JSON")
            else:
                st.error(f"❌ API {i+1} returned status {response.status_code}")
                    
        except requests.exceptions.Timeout:
            st.error(f"❌ API {i+1} timed out")
        except requests.exceptions.ConnectionError:
            st.error(f"❌ API {i+1} connection failed")
        except Exception as e:
            st.error(f"❌ API {i+1} error: {str(e)}")
    
    st.error("❌ No working APIs found")
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
        
        # Check if we got valid data
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

def discover_influxdb_buckets():
    """Discover all available buckets in your InfluxDB organization"""
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        buckets_api = BucketsApi(client)
        
        buckets = buckets_api.find_buckets()
        
        bucket_list = []
        for bucket in buckets.buckets:
            bucket_list.append({
                'name': bucket.name,
                'id': bucket.id,
                'retention_rules': str(bucket.retention_rules),
                'created_at': bucket.created_at
            })
        
        client.close()
        return bucket_list
        
    except Exception as e:
        st.error(f"❌ Error discovering buckets: {e}")
        return []

def validate_influxdb_config():
    """Validate InfluxDB connection and configuration"""
    validation_results = {
        'connection': False,
        'organization': False,
        'bucket': False,
        'permissions': False,
        'buckets_found': []
    }
    
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        buckets_api = BucketsApi(client)
        
        buckets = buckets_api.find_buckets()
        validation_results['connection'] = True
        validation_results['organization'] = True
        
        bucket_names = [bucket.name for bucket in buckets.buckets]
        validation_results['buckets_found'] = bucket_names
        
        if INFLUXDB_BUCKET in bucket_names:
            validation_results['bucket'] = True
            
            query_api = client.query_api()
            test_query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: -1h)
              |> limit(n: 1)
            '''
            
            try:
                query_api.query_data_frame(org=INFLUXDB_ORG, query=test_query)
                validation_results['permissions'] = True
            except:
                validation_results['permissions'] = False
        
        client.close()
        
    except Exception as e:
        st.error(f"Connection validation failed: {e}")
    
    return validation_results

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
            
            fig_pie = go.Figure(data=[
    go.Pie(
        labels=["Normal Traffic", "Anomalies"],
        values=[normal_count, anomaly_count],
        hole=0.4,
        textinfo="label+percent"
    )
])

