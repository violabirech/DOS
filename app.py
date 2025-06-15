import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
import plotly.figure_factory as ff
from plotly.subplots import make_subplots
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import time
import json
import random

# --- Page Setup ---
st.set_page_config(
    page_title="🔍 Anomaly Detection Dashboard", 
    layout="wide",
    page_icon="🔍"
)

# --- Custom CSS ---
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 20px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .metric-card {
        background: white;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        border-left: 4px solid #667eea;
        margin: 10px 0;
    }
    .status-good { color: #28a745; font-weight: bold; }
    .status-warning { color: #ffc107; font-weight: bold; }
    .status-danger { color: #dc3545; font-weight: bold; }
    .sidebar-section {
        background: #f8f9fa;
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
        border: 1px solid #dee2e6;
    }
    .diagnostic-box {
        background: #f8f9fa;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #17a2b8;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

# --- Configuration ---
DEFAULT_API_URL = "https://api.example.com/anomaly-detect"  # Mock API endpoint
MOCK_MODE = True  # Set to True to use simulated data

# --- Initialize Session State ---
if 'data_history' not in st.session_state:
    st.session_state.data_history = []
if 'predictions_history' not in st.session_state:
    st.session_state.predictions_history = []
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = False

# --- Helper Functions ---
def generate_mock_data(n_samples=100, anomaly_rate=0.1):
    """Generate mock sensor data with some anomalies"""
    np.random.seed(42)
    
    # Normal data
    normal_samples = int(n_samples * (1 - anomaly_rate))
    anomaly_samples = n_samples - normal_samples
    
    # Generate normal data (multivariate normal distribution)
    normal_data = np.random.multivariate_normal(
        mean=[50, 25, 75], 
        cov=[[10, 2, 1], [2, 5, 0.5], [1, 0.5, 8]], 
        size=normal_samples
    )
    
    # Generate anomaly data (shifted mean and higher variance)
    anomaly_data = np.random.multivariate_normal(
        mean=[80, 60, 30], 
        cov=[[50, 10, 5], [10, 25, 2], [5, 2, 20]], 
        size=anomaly_samples
    )
    
    # Combine data
    data = np.vstack([normal_data, anomaly_data])
    labels = np.hstack([np.zeros(normal_samples), np.ones(anomaly_samples)])
    
    # Shuffle
    indices = np.random.permutation(len(data))
    data = data[indices]
    labels = labels[indices]
    
    # Create timestamps
    timestamps = [datetime.now() - timedelta(minutes=i) for i in range(n_samples-1, -1, -1)]
    
    df = pd.DataFrame(data, columns=['sensor_1', 'sensor_2', 'sensor_3'])
    df['timestamp'] = timestamps
    df['true_label'] = labels
    df['id'] = range(len(df))
    
    return df

def mock_api_prediction(sensor_1, sensor_2, sensor_3):
    """Mock API prediction using Isolation Forest"""
    # Simple anomaly detection logic
    data_point = np.array([[sensor_1, sensor_2, sensor_3]])
    
    # Mock reconstruction error (distance from normal range)
    normal_means = np.array([50, 25, 75])
    reconstruction_error = np.linalg.norm(data_point - normal_means) / 100
    
    # Determine anomaly based on threshold
    anomaly = reconstruction_error > 0.5
    confidence = min(reconstruction_error * 2, 1.0)
    
    return {
        "reconstruction_error": float(reconstruction_error),
        "anomaly": bool(anomaly),
        "confidence": float(confidence),
        "prediction": "anomaly" if anomaly else "normal"
    }

def get_status_color(value, thresholds):
    """Get status color based on thresholds"""
    if value < thresholds[0]:
        return "status-good"
    elif value < thresholds[1]:
        return "status-warning"
    else:
        return "status-danger"

# --- Sidebar Configuration ---
st.sidebar.title("🎛️ Control Panel")

# Data Source Configuration
st.sidebar.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
st.sidebar.subheader("📊 Data Source")
data_source = st.sidebar.selectbox(
    "Select Data Source:", 
    ["Mock Data (Demo)", "Live API", "File Upload", "Database Connection"]
)

if data_source == "Live API":
    api_url = st.sidebar.text_input("API URL:", value=DEFAULT_API_URL)
    api_token = st.sidebar.text_input("API Token:", type="password")
    MOCK_MODE = False
else:
    MOCK_MODE = True

st.sidebar.markdown('</div>', unsafe_allow_html=True)

# Time Configuration
st.sidebar.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
st.sidebar.subheader("⏰ Time Settings")
time_window = st.sidebar.selectbox(
    "Time Range", 
    ["-5m", "-15m", "-1h", "-6h", "-12h", "-1d", "-7d", "-30d"], 
    index=2
)
refresh_interval = st.sidebar.slider("Refresh Interval (seconds)", 1, 60, 5)
st.sidebar.markdown('</div>', unsafe_allow_html=True)

# Detection Configuration
st.sidebar.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
st.sidebar.subheader("🔍 Detection Settings")
anomaly_threshold = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.5, 0.01)
confidence_threshold = st.sidebar.slider("Confidence Threshold", 0.1, 1.0, 0.7, 0.1)
batch_size = st.sidebar.number_input("Batch Size", 10, 1000, 100)
st.sidebar.markdown('</div>', unsafe_allow_html=True)

# Advanced Settings
st.sidebar.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
st.sidebar.subheader("⚙️ Advanced Settings")
debug_mode = st.sidebar.checkbox("Debug Mode", value=False)
show_raw_data = st.sidebar.checkbox("Show Raw Data", value=False)
enable_alerts = st.sidebar.checkbox("Enable Alerts", value=True)
st.sidebar.markdown('</div>', unsafe_allow_html=True)

# Auto-refresh
st.sidebar.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
st.sidebar.subheader("🔄 Auto Refresh")
auto_refresh = st.sidebar.checkbox("Enable Auto Refresh")
if auto_refresh:
    st.sidebar.info(f"Page will refresh every {refresh_interval} seconds")
    time.sleep(refresh_interval)
    st.rerun()
st.sidebar.markdown('</div>', unsafe_allow_html=True)

# --- Main Dashboard ---
st.markdown('<div class="main-header"><h1>🔍 Anomaly Detection Dashboard</h1><p>Real-time monitoring and anomaly detection system</p></div>', unsafe_allow_html=True)

# --- Navigation Tabs ---
tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Overview", "🔍 Detection", "📈 Analytics", "🛠️ Diagnostics", "⚙️ Settings"])

with tab1:
    st.header("📊 System Overview")
    
    # Generate or load data
    if MOCK_MODE:
        df = generate_mock_data(batch_size)
        st.info("Using mock data for demonstration")
    else:
        st.warning("Live API mode selected but not implemented - using mock data")
        df = generate_mock_data(batch_size)
    
    # Key Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    total_records = len(df)
    anomaly_count = int(df['true_label'].sum()) if 'true_label' in df.columns else 0
    anomaly_rate = (anomaly_count / total_records) * 100 if total_records > 0 else 0
    
    col1.metric("Total Records", total_records)
    col2.metric("Normal Records", total_records - anomaly_count)
    col3.metric("Anomalies", anomaly_count)
    col4.metric("Anomaly Rate", f"{anomaly_rate:.1f}%")
    
    # Status indicators
    st.subheader("🚦 System Status")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        data_freshness = "Good"  # Mock status
        st.markdown(f'**Data Freshness:** <span class="status-good">{data_freshness}</span>', unsafe_allow_html=True)
    
    with col2:
        api_status = "Connected" if not MOCK_MODE else "Mock Mode"
        status_class = "status-good" if api_status == "Connected" else "status-warning"
        st.markdown(f'**API Status:** <span class="{status_class}">{api_status}</span>', unsafe_allow_html=True)
    
    with col3:
        detection_status = "Active"
        st.markdown(f'**Detection:** <span class="status-good">{detection_status}</span>', unsafe_allow_html=True)
    
    # Recent Activity Timeline
    st.subheader("⏱️ Recent Activity")
    
    # Create timeline chart
    fig_timeline = px.scatter(
        df.tail(50), 
        x='timestamp', 
        y='sensor_1',
        color='true_label',
        title="Recent Sensor Readings",
        color_discrete_map={0: 'blue', 1: 'red'},
        labels={'true_label': 'Anomaly', 'sensor_1': 'Sensor Value'}
    )
    fig_timeline.update_layout(height=400)
    st.plotly_chart(fig_timeline, use_container_width=True)

with tab2:
    st.header("🔍 Anomaly Detection")
    
    # Run Detection
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.subheader("Detection Results")
    
    with col2:
        if st.button("🔄 Run Detection", type="primary"):
            with st.spinner("Running anomaly detection..."):
                # Simulate detection process
                progress_bar = st.progress(0)
                predictions = []
                
                for i, (_, row) in enumerate(df.iterrows()):
                    # Mock API call
                    pred = mock_api_prediction(
                        row['sensor_1'], 
                        row['sensor_2'], 
                        row['sensor_3']
                    )
                    pred.update({
                        'timestamp': row['timestamp'],
                        'sensor_1': row['sensor_1'],
                        'sensor_2': row['sensor_2'],
                        'sensor_3': row['sensor_3'],
                        'true_label': row['true_label']
                    })
                    predictions.append(pred)
                    
                    progress_bar.progress((i + 1) / len(df))
                    
                    # Limit for demo
                    if i >= 99:
                        break
                
                st.session_state.predictions_history = predictions
                progress_bar.empty()
                st.success(f"Detection completed! Processed {len(predictions)} records")
    
    # Display Results
    if st.session_state.predictions_history:
        pred_df = pd.DataFrame(st.session_state.predictions_history)
        
        # Detection Metrics
        col1, col2, col3, col4 = st.columns(4)
        
        detected_anomalies = pred_df['anomaly'].sum()
        high_confidence = (pred_df['confidence'] > confidence_threshold).sum()
        avg_reconstruction_error = pred_df['reconstruction_error'].mean()
        
        col1.metric("Detected Anomalies", detected_anomalies)
        col2.metric("High Confidence", high_confidence)
        col3.metric("Avg Reconstruction Error", f"{avg_reconstruction_error:.3f}")
        col4.metric("Detection Rate", f"{(detected_anomalies/len(pred_df)*100):.1f}%")
        
        # Visualization
        fig_detection = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Reconstruction Error Over Time', 'Confidence Distribution', 
                          'Sensor Correlation', 'Anomaly Distribution'),
            specs=[[{"secondary_y": True}, {"type": "histogram"}],
                   [{"type": "scatter"}, {"type": "pie"}]]
        )
        
        # Reconstruction error timeline
        fig_detection.add_trace(
            go.Scatter(
                x=pred_df['timestamp'],
                y=pred_df['reconstruction_error'],
                mode='lines+markers',
                name='Reconstruction Error',
                marker=dict(color=pred_df['anomaly'], colorscale='RdYlBu', size=8)
            ),
            row=1, col=1
        )
        
        # Add threshold line
        fig_detection.add_hline(
            y=anomaly_threshold, 
            line_dash="dash", 
            line_color="red",
            row=1, col=1
        )
        
        # Confidence histogram
        fig_detection.add_trace(
            go.Histogram(x=pred_df['confidence'], name='Confidence', nbinsx=20),
            row=1, col=2
        )
        
        # Sensor correlation
        fig_detection.add_trace(
            go.Scatter(
                x=pred_df['sensor_1'],
                y=pred_df['sensor_2'],
                mode='markers',
                marker=dict(
                    color=pred_df['anomaly'],
                    colorscale='RdYlBu',
                    size=8
                ),
                name='Sensor Correlation'
            ),
            row=2, col=1
        )
        
        # Anomaly distribution pie chart
        anomaly_counts = pred_df['anomaly'].value_counts()
        fig_detection.add_trace(
            go.Pie(
                labels=['Normal', 'Anomaly'],
                values=[anomaly_counts.get(False, 0), anomaly_counts.get(True, 0)],
                name="Distribution"
            ),
            row=2, col=2
        )
        
        fig_detection.update_layout(height=800, showlegend=True)
        st.plotly_chart(fig_detection, use_container_width=True)
        
        # Data Table
        st.subheader("📋 Detection Results Table")
        display_df = pred_df[[
            'timestamp', 'sensor_1', 'sensor_2', 'sensor_3',
            'reconstruction_error', 'confidence', 'anomaly', 'prediction'
        ]].copy()
        
        # Highlight anomalies
        def highlight_anomalies(row):
            return ['background-color: #ffcccc' if row['anomaly'] else '' for _ in row]
        
        st.dataframe(
            display_df.style.apply(highlight_anomalies, axis=1),
            use_container_width=True
        )

with tab3:
    st.header("📈 Analytics & Performance")
    
    if st.session_state.predictions_history:
        pred_df = pd.DataFrame(st.session_state.predictions_history)
        
        # Performance Metrics (if true labels available)
        if 'true_label' in pred_df.columns:
            st.subheader("🎯 Model Performance")
            
            y_true = pred_df['true_label'].astype(bool)
            y_pred = pred_df['anomaly'].astype(bool)
            
            # Calculate metrics
            accuracy = accuracy_score(y_true, y_pred)
            precision = precision_score(y_true, y_pred, zero_division=0)
            recall = recall_score(y_true, y_pred, zero_division=0)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Accuracy", f"{accuracy:.3f}")
            col2.metric("Precision", f"{precision:.3f}")
            col3.metric("Recall", f"{recall:.3f}")
            col4.metric("F1-Score", f"{f1:.3f}")
            
            # Confusion Matrix
            cm = confusion_matrix(y_true, y_pred)
            fig_cm = ff.create_annotated_heatmap(
                cm, x=['Normal', 'Anomaly'], y=['Normal', 'Anomaly'],
                annotation_text=cm, colorscale='Blues'
            )
            fig_cm.update_layout(title="Confusion Matrix", width=500, height=400)
            st.plotly_chart(fig_cm, use_container_width=True)
        
        # Temporal Analysis
        st.subheader("⏰ Temporal Analysis")
        
        # Anomaly rate over time
        pred_df['hour'] = pd.to_datetime(pred_df['timestamp']).dt.hour
        hourly_anomalies = pred_df.groupby('hour')['anomaly'].agg(['count', 'sum']).reset_index()
        hourly_anomalies['anomaly_rate'] = (hourly_anomalies['sum'] / hourly_anomalies['count']) * 100
        
        fig_temporal = px.bar(
            hourly_anomalies, 
            x='hour', 
            y='anomaly_rate',
            title='Anomaly Rate by Hour',
            labels={'anomaly_rate': 'Anomaly Rate (%)', 'hour': 'Hour of Day'}
        )
        st.plotly_chart(fig_temporal, use_container_width=True)
        
        # Feature Analysis
        st.subheader("🔬 Feature Analysis")
        
        # Box plots for each sensor
        fig_features = make_subplots(
            rows=1, cols=3,
            subplot_titles=('Sensor 1', 'Sensor 2', 'Sensor 3')
        )
        
        for i, sensor in enumerate(['sensor_1', 'sensor_2', 'sensor_3'], 1):
            normal_data = pred_df[pred_df['anomaly'] == False][sensor]
            anomaly_data = pred_df[pred_df['anomaly'] == True][sensor]
            
            fig_features.add_trace(
                go.Box(y=normal_data, name='Normal', showlegend=i==1),
                row=1, col=i
            )
            fig_features.add_trace(
                go.Box(y=anomaly_data, name='Anomaly', showlegend=i==1),
                row=1, col=i
            )
        
        fig_features.update_layout(height=400, title="Feature Distribution: Normal vs Anomaly")
        st.plotly_chart(fig_features, use_container_width=True)
    
    else:
        st.info("Run anomaly detection first to see analytics")

with tab4:
    st.header("🛠️ System Diagnostics")
    
    # Connection Test
    st.subheader("🔌 Connection Test")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="diagnostic-box">', unsafe_allow_html=True)
        st.write("**System Information:**")
        st.write(f"✅ Data Source: {data_source}")
        st.write(f"✅ Mode: {'Mock' if MOCK_MODE else 'Live'}")
        st.write(f"✅ Batch Size: {batch_size}")
        st.write(f"✅ Threshold: {anomaly_threshold}")
        st.write(f"✅ Time Window: {time_window}")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="diagnostic-box">', unsafe_allow_html=True)
        st.write("**Performance Metrics:**")
        
        # Mock performance metrics
        latency = random.uniform(10, 50)
        throughput = random.uniform(100, 500)
        memory_usage = random.uniform(20, 80)
        
        latency_color = get_status_color(latency, [30, 45])
        throughput_color = get_status_color(throughput, [200, 400])
        memory_color = get_status_color(memory_usage, [60, 80])
        
        st.markdown(f'**API Latency:** <span class="{latency_color}">{latency:.1f}ms</span>', unsafe_allow_html=True)
        st.markdown(f'**Throughput:** <span class="{throughput_color}">{throughput:.0f} req/sec</span>', unsafe_allow_html=True)
        st.markdown(f'**Memory Usage:** <span class="{memory_color}">{memory_usage:.1f}%</span>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Data Quality Check
    st.subheader("🔍 Data Quality Assessment")
    
    if MOCK_MODE:
        df = generate_mock_data(100)
        
        # Check data quality
        missing_data = df.isnull().sum()
        data_types = df.dtypes
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Missing Data Check:**")
            for column, missing_count in missing_data.items():
                status = "✅" if missing_count == 0 else "⚠️"
                st.write(f"{status} {column}: {missing_count} missing values")
        
        with col2:
            st.write("**Data Types:**")
            for column, dtype in data_types.items():
                st.write(f"📊 {column}: {dtype}")
    
    # Debug Information
    if debug_mode:
        st.subheader("🐛 Debug Information")
        
        with st.expander("Session State"):
            st.json(dict(st.session_state))
        
        with st.expander("Configuration"):
            config = {
                "data_source": data_source,
                "mock_mode": MOCK_MODE,
                "time_window": time_window,
                "anomaly_threshold": anomaly_threshold,
                "batch_size": batch_size,
                "debug_mode": debug_mode
            }
            st.json(config)
        
        if st.session_state.predictions_history:
            with st.expander("Sample Predictions"):
                st.json(st.session_state.predictions_history[:3])

with tab5:
    st.header("⚙️ Configuration Settings")
    
    # Model Configuration
    st.subheader("🤖 Model Settings")
    
    col1, col2 = st.columns(2)
    
    with col1:
        model_type = st.selectbox("Detection Algorithm", 
                                ["Isolation Forest", "Local Outlier Factor", "One-Class SVM", "Autoencoder"])
        contamination = st.slider("Expected Contamination", 0.01, 0.5, 0.1)
        
    with col2:
        n_estimators = st.number_input("Number of Estimators", 50, 500, 100)
        max_samples = st.selectbox("Max Samples", ["auto", 256, 512, 1024])
    
    # Alert Configuration
    st.subheader("🚨 Alert Settings")
    
    col1, col2 = st.columns(2)
    
    with col1:
        email_alerts = st.checkbox("Email Alerts", value=False)
        if email_alerts:
            email_recipients = st.text_area("Email Recipients (one per line)")
    
    with col2:
        slack_alerts = st.checkbox("Slack Notifications", value=False)
        if slack_alerts:
            slack_webhook = st.text_input("Slack Webhook URL", type="password")
    
    # Data Retention
    st.subheader("💾 Data Retention")
    
    col1, col2 = st.columns(2)
    
    with col1:
        retention_period = st.selectbox("Data Retention Period", 
                                      ["7 days", "30 days", "90 days", "1 year", "Forever"])
        
    with col2:
        export_format = st.selectbox("Export Format", ["CSV", "JSON", "Parquet"])
    
    # Save Settings
    if st.button("💾 Save Configuration", type="primary"):
        config = {
            "model_type": model_type,
            "contamination": contamination,
            "n_estimators": n_estimators,
            "max_samples": max_samples,
            "email_alerts": email_alerts,
            "slack_alerts": slack_alerts,
            "retention_period": retention_period,
            "export_format": export_format
        }
        
        # In a real app, you would save this to a database or config file
        st.success("Configuration saved successfully!")
        st.json(config)

# --- Footer ---
st.markdown("---")
col1, col2, col3 = st.columns(3)

with col1:
    st.write("🔄 **Last Updated:**")
    st.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

with col2:
    st.write("📊 **Total Sessions:**")
    st.write(f"{len(st.session_state.predictions_history)} predictions")

with col3:
    st.write("⚡ **Status:**")
    st.write("🟢 System Online")

# Auto-refresh logic
if auto_refresh and not st.session_state.get('refreshing', False):
    st.session_state.refreshing = True
    time.sleep(refresh_interval)
    st.session_state.refreshing = False
    st.rerun()