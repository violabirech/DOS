import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime, timedelta
import time
from influxdb_client import InfluxDBClient
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.figure_factory as ff

# --- Page Setup ---
st.set_page_config(page_title="🚀 DoS Detection Dashboard", layout="wide")

# --- Configuration ---
API_URL = "https://violabirech-dos-anomalies-detection.hf.space/predict"
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

# --- Sidebar Controls ---
st.sidebar.title("🔧 Controls")

# Auto-refresh settings
auto_refresh = st.sidebar.checkbox("Auto Refresh", value=True)
refresh_interval = st.sidebar.selectbox("Refresh Interval", [5, 10, 15, 30, 60], index=1)

time_window = st.sidebar.selectbox("Time Range", ["-5m", "-15m", "-1h", "-6h", "-12h", "-1d", "-7d", "-30d"], index=2)
thresh = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
max_records = st.sidebar.slider("Max Records to Process", 50, 500, 200, 50)

# Monitoring controls
st.sidebar.markdown("---")
st.sidebar.subheader("🎛️ Monitoring Controls")

col1, col2 = st.sidebar.columns(2)
with col1:
    if st.button("▶️ Start", type="primary"):
        st.session_state.monitoring_active = True
with col2:
    if st.button("⏹️ Stop"):
        st.session_state.monitoring_active = False

# Clear data button
if st.sidebar.button("🗑️ Clear History"):
    st.session_state.historical_data = []
    st.session_state.anomaly_alerts = []
    st.rerun()

# Configuration override
st.sidebar.markdown("---")
st.sidebar.subheader("🔧 Configuration Override")
custom_bucket = st.sidebar.text_input("Bucket Name", value=INFLUXDB_BUCKET)
custom_measurement = st.sidebar.text_input("Measurement Name", value=INFLUXDB_MEASUREMENT)
custom_org = st.sidebar.text_input("Organization", value=INFLUXDB_ORG)

# Update variables if overridden
if custom_bucket:
    INFLUXDB_BUCKET = custom_bucket
if custom_measurement:
    INFLUXDB_MEASUREMENT = custom_measurement
if custom_org:
    INFLUXDB_ORG = custom_org

# --- Title ---
st.title("🚀 Real-Time DoS Anomaly Detection Dashboard")

# Status indicator
status_col1, status_col2, status_col3 = st.columns([1, 1, 2])
with status_col1:
    if st.session_state.monitoring_active:
        st.success("🟢 ACTIVE")
    else:
        st.error("🔴 STOPPED")

with status_col2:
    st.info(f"⏱️ Refresh: {refresh_interval}s")

with status_col3:
    if st.session_state.historical_data:
        last_update = max([d['timestamp'] for d in st.session_state.historical_data])
        st.write(f"📅 Last Update: {last_update}")

# --- Navigation Tabs ---
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🏠 Overview", "📊 Live Stream", "⚙️ Manual Entry", "📈 Metrics & Alerts", "🔧 Diagnostics"])

# --- Helper Functions ---
@st.cache_data(ttl=30)
def get_influx_data(time_range, bucket, measurement, org):
    """Fetch data from InfluxDB with caching"""
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=org)
        query_api = client.query_api()
        
        query = f'''
        from(bucket: "{bucket}")
          |> range(start: {time_range})
          |> filter(fn: (r) => r._measurement == "{measurement}")
          |> filter(fn: (r) => r._field == "inter_arrival_time" or r._field == "packet_length" or r._field == "label")
          |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
          |> sort(columns: ["_time"])
          |> limit(n: {max_records})
        '''
        
        data = query_api.query_data_frame(org=org, query=query)
        if isinstance(data, list) and data:
            data = pd.concat(data, ignore_index=True)
        
        client.close()
        return data
        
    except Exception as e:
        st.error(f"InfluxDB Error: {e}")
        return None

def predict_anomaly(inter_arrival_time, packet_length):
    """Make prediction using the API"""
    try:
        payload = {
            "inter_arrival_time": float(inter_arrival_time),
            "packet_length": float(packet_length)
        }
        
        response = requests.post(API_URL, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()
        
    except Exception as e:
        return {"error": str(e)}

def process_batch_predictions(df):
    """Process a batch of predictions"""
    predictions = []
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for i, (index, row) in enumerate(df.iterrows()):
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
                
                # Add to historical data
                st.session_state.historical_data.append(result)
                
                # Check for anomalies and add alerts
                if result.get('anomaly', 0) == 1:
                    alert = {
                        "timestamp": result["timestamp"],
                        "severity": "HIGH" if result.get('reconstruction_error', 0) > thresh * 2 else "MEDIUM",
                        "message": f"Anomaly detected: Reconstruction error {result.get('reconstruction_error', 0):.4f}",
                        "source_ip": result.get("source_ip", "Unknown")
                    }
                    st.session_state.anomaly_alerts.append(alert)
            
            progress = (i + 1) / len(df)
            progress_bar.progress(progress)
            status_text.text(f"Processed {i + 1}/{len(df)} records")
            
        except Exception as e:
            continue
    
    progress_bar.empty()
    status_text.empty()
    
    # Limit historical data size
    if len(st.session_state.historical_data) > 1000:
        st.session_state.historical_data = st.session_state.historical_data[-1000:]
    
    if len(st.session_state.anomaly_alerts) > 100:
        st.session_state.anomaly_alerts = st.session_state.anomaly_alerts[-100:]
    
    return predictions

# --- Tab 1: Overview ---
with tab1:
    st.subheader("📊 Analytical Dashboard")
    
    # Metrics overview
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
        
        # Anomaly distribution pie chart
        st.subheader("Anomaly Distribution")
        
        fig_pie = go.Figure(data=[go.Pie(
            labels=['Normal', 'Attack'],
            values=[normal_count, anomaly_count],
            hole=.3,
            marker_colors=['#1f77b4', '#87ceeb']
        )])
        
        fig_pie.update_layout(
            title="Anomaly Types",
            annotations=[dict(text=f'{anomaly_rate:.1f}%', x=0.5, y=0.5, font_size=20, showarrow=False)]
        )
        
        st.plotly_chart(fig_pie, use_container_width=True)
        
        # Time series plot
        if len(df_hist) > 1:
            st.subheader("📈 Real-Time Anomaly Detection")
            
            df_hist['timestamp'] = pd.to_datetime(df_hist['timestamp'])
            df_hist = df_hist.sort_values('timestamp')
            
            fig_ts = px.line(
                df_hist, 
                x="timestamp", 
                y="reconstruction_error",
                color="anomaly",
                title="Reconstruction Error Over Time",
                color_discrete_map={0: 'blue', 1: 'red'}
            )
            fig_ts.add_hline(y=thresh, line_dash="dash", line_color="green", annotation_text="Threshold")
            st.plotly_chart(fig_ts, use_container_width=True)
    
    else:
        st.info("📊 No data collected yet. Start monitoring to see analytics.")

# --- Tab 2: Live Stream ---
with tab2:
    st.subheader("📡 Real-Time Monitoring")
    
    # Auto-refresh logic
    if auto_refresh and st.session_state.monitoring_active:
        placeholder = st.empty()
        
        while st.session_state.monitoring_active:
            with placeholder.container():
                # Fetch fresh data
                df = get_influx_data(time_window, INFLUXDB_BUCKET, INFLUXDB_MEASUREMENT, INFLUXDB_ORG)
                
                if df is not None and not df.empty:
                    # Check required columns
                    required_cols = ['inter_arrival_time', 'packet_length']
                    available_cols = [col for col in required_cols if col in df.columns]
                    
                    if len(available_cols) >= 2:
                        df_clean = df.dropna(subset=available_cols)
                        
                        if len(df_clean) > 0:
                            st.success(f"✅ Processing {len(df_clean)} records from InfluxDB")
                            
                            # Process predictions
                            predictions = process_batch_predictions(df_clean)
                            
                            if predictions:
                                df_pred = pd.DataFrame(predictions)
                                df_pred["timestamp"] = pd.to_datetime(df_pred["timestamp"])
                                
                                # Display live data table
                                st.subheader("📋 Live Data Stream")
                                
                                # Color-code anomalies
                                def highlight_anomalies(row):
                                    if row['anomaly'] == 1:
                                        return ['background-color: #ffcccc'] * len(row)
                                    return [''] * len(row)
                                
                                display_df = df_pred[[
                                    "timestamp", "source_ip", "dest_ip", "inter_arrival_time", 
                                    "dns_rate", "reconstruction_error", "anomaly", "label"
                                ]].copy()
                                
                                styled_df = display_df.style.apply(highlight_anomalies, axis=1)
                                st.dataframe(styled_df, use_container_width=True, height=400)
                                
                            else:
                                st.warning("⚠️ No predictions generated")
                        else:
                            st.warning("⚠️ No valid data after cleaning")
                    else:
                        st.error(f"❌ Missing required columns. Available: {df.columns.tolist()}")
                else:
                    st.warning("⚠️ No data retrieved from InfluxDB")
            
            # Wait before next refresh
            time.sleep(refresh_interval)
            st.rerun()
    
    elif st.session_state.monitoring_active:
        st.info("🔄 Manual refresh mode. Click 'Refresh' to update data.")
        if st.button("🔄 Refresh Data"):
            st.rerun()
    
    else:
        st.info("▶️ Click 'Start' in the sidebar to begin monitoring")

# --- Tab 3: Manual Entry ---
with tab3:
    st.subheader("🔧 Manual Entry for Testing")
    
    col1, col2 = st.columns(2)
    
    with col1:
        inter_arrival_time = st.number_input("Inter Arrival Time", value=0.02, format="%.6f")
    
    with col2:
        dns_rate = st.number_input("DNS Rate", value=5.00, format="%.2f")
    
    if st.button("🔍 Predict Anomaly", type="primary"):
        with st.spinner("Making prediction..."):
            result = predict_anomaly(inter_arrival_time, dns_rate)
            
            if 'error' in result:
                st.error(f"❌ Error: {result['error']}")
            else:
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if result.get('anomaly', 0) == 1:
                        st.error("🚨 ANOMALY DETECTED")
                    else:
                        st.success("✅ NORMAL TRAFFIC")
                
                with col2:
                    st.metric("Reconstruction Error", f"{result.get('reconstruction_error', 0):.6f}")
                
                with col3:
                    st.metric("Threshold", f"{thresh:.2f}")

# --- Tab 4: Metrics & Alerts ---
with tab4:
    st.subheader("📈 Metrics & Performance")
    
    if st.session_state.anomaly_alerts:
        st.subheader("🚨 Recent Alerts")
        
        alerts_df = pd.DataFrame(st.session_state.anomaly_alerts)
        alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
        alerts_df = alerts_df.sort_values('timestamp', ascending=False)
        
        # Color code by severity
        def color_severity(row):
            if row['severity'] == 'HIGH':
                return ['background-color: #ffcccc'] * len(row)
            elif row['severity'] == 'MEDIUM':
                return ['background-color: #fff2cc'] * len(row)
            return ['background-color: #ccffcc'] * len(row)
        
        styled_alerts = alerts_df.style.apply(color_severity, axis=1)
        st.dataframe(styled_alerts, use_container_width=True)
        
        # Alert statistics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            high_alerts = len(alerts_df[alerts_df['severity'] == 'HIGH'])
            st.metric("High Severity", high_alerts)
        
        with col2:
            medium_alerts = len(alerts_df[alerts_df['severity'] == 'MEDIUM'])
            st.metric("Medium Severity", medium_alerts)
        
        with col3:
            recent_alerts = len(alerts_df[alerts_df['timestamp'] > datetime.now() - timedelta(hours=1)])
            st.metric("Last Hour", recent_alerts)
    
    else:
        st.info("📊 No alerts generated yet.")
    
    # Performance metrics
    if st.session_state.historical_data:
        st.subheader("⚡ Performance Metrics")
        
        df_perf = pd.DataFrame(st.session_state.historical_data)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            avg_reconstruction_error = df_perf['reconstruction_error'].mean() if 'reconstruction_error' in df_perf.columns else 0
            st.metric("Avg Reconstruction Error", f"{avg_reconstruction_error:.4f}")
        
        with col2:
            max_reconstruction_error = df_perf['reconstruction_error'].max() if 'reconstruction_error' in df_perf.columns else 0
            st.metric("Max Reconstruction Error", f"{max_reconstruction_error:.4f}")
        
        with col3:
            detection_rate = (df_perf['anomaly'].sum() / len(df_perf) * 100) if 'anomaly' in df_perf.columns and len(df_perf) > 0 else 0
            st.metric("Detection Rate", f"{detection_rate:.1f}%")
        
        with col4:
            processing_rate = len(df_perf)
            st.metric("Records Processed", processing_rate)

# --- Tab 5: Diagnostics ---
with tab5:
    st.subheader("🔧 Enhanced Diagnostics")
    
    # Connection test
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        query_api = client.query_api()
        
        st.success("✅ InfluxDB connection successful")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write(f"🔗 **URL:** `{INFLUXDB_URL}`")
            st.write(f"🏢 **Organization:** `{INFLUXDB_ORG}`")
            st.write(f"🪣 **Bucket:** `{INFLUXDB_BUCKET}`")
        
        with col2:
            st.write(f"📊 **Measurement:** `{INFLUXDB_MEASUREMENT}`")
            st.write(f"⏰ **Time Range:** `{time_window}`")
            st.write(f"📈 **Max Records:** `{max_records}`")
        
        # Test data availability
        test_data = get_influx_data(time_window, INFLUXDB_BUCKET, INFLUXDB_MEASUREMENT, INFLUXDB_ORG)
        
        if test_data is not None and not test_data.empty:
            st.success(f"✅ Data available: {len(test_data)} records")
            
            with st.expander("🔍 Sample Data"):
                st.dataframe(test_data.head(10))
        else:
            st.warning("⚠️ No data found in specified time range")
        
        client.close()
        
    except Exception as e:
        st.error(f"❌ Connection failed: {e}")
    
    # API test
    st.subheader("🔌 API Status")
    try:
        test_result = predict_anomaly(0.02, 5.0)
        if 'error' in test_result:
            st.error(f"❌ API Error: {test_result['error']}")
        else:
            st.success("✅ ML API is responding")
    except Exception as e:
        st.error(f"❌ API connection failed: {e}")

# --- Auto-refresh for the entire app ---
if auto_refresh and st.session_state.monitoring_active:
    time.sleep(1)  # Small delay to prevent too frequent refreshes
    st.rerun()

# --- Footer ---
st.markdown("---")
st.markdown("🚀 **DoS Anomaly Detection Dashboard** | Real-time network traffic monitoring and analysis")
