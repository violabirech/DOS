import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime
from influxdb_client import InfluxDBClient
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import plotly.express as px
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

# --- Sidebar Controls ---
st.sidebar.title("Controls")
time_window = st.sidebar.selectbox("Time Range", ["-1h", "-6h", "-12h", "-1d", "-7d"], index=0)
thresh = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
debug_mode = st.sidebar.checkbox("Show Debug Info", value=True)

# --- Title ---
st.title("🚀 DoS Anomaly Detection Dashboard")

# --- InfluxDB Connection ---
client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
query_api = client.query_api()

# --- Debug Section ---
if debug_mode:
    st.subheader("🔧 Debug Information")
    
    # Check connection and basic info
    try:
        # Check what measurements exist
        debug_query_measurements = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: {time_window})
          |> group()
          |> distinct(column: "_measurement")
        '''
        
        # Check what fields exist in your measurement
        debug_query_fields = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: {time_window})
          |> filter(fn: (r) => r._measurement == "{INFLUXDB_MEASUREMENT}")
          |> group()
          |> distinct(column: "_field")
        '''
        
        # Check raw data structure
        debug_query_sample = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: {time_window})
          |> filter(fn: (r) => r._measurement == "{INFLUXDB_MEASUREMENT}")
          |> limit(n: 10)
        '''
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Connection Info:**")
            st.write(f"- Bucket: `{INFLUXDB_BUCKET}`")
            st.write(f"- Measurement: `{INFLUXDB_MEASUREMENT}`")
            st.write(f"- Time Range: `{time_window}`")
            st.write(f"- Organization: `{INFLUXDB_ORG}`")
        
        with col2:
            # Debug measurements
            try:
                measurements_df = query_api.query_data_frame(org=INFLUXDB_ORG, query=debug_query_measurements)
                if isinstance(measurements_df, list):
                    measurements_df = pd.concat(measurements_df, ignore_index=True)
                
                if not measurements_df.empty and '_value' in measurements_df.columns:
                    available_measurements = measurements_df['_value'].unique().tolist()
                    st.write("**Available Measurements:**")
                    for m in available_measurements:
                        if m == INFLUXDB_MEASUREMENT:
                            st.write(f"✅ `{m}`")
                        else:
                            st.write(f"- `{m}`")
                else:
                    st.warning("❌ No measurements found!")
            except Exception as e:
                st.error(f"Cannot fetch measurements: {e}")
        
        # Debug fields
        try:
            fields_df = query_api.query_data_frame(org=INFLUXDB_ORG, query=debug_query_fields)
            if isinstance(fields_df, list):
                fields_df = pd.concat(fields_df, ignore_index=True)
            
            if not fields_df.empty and '_value' in fields_df.columns:
                available_fields = fields_df['_value'].unique().tolist()
                st.write("**Available Fields in Measurement:**")
                required_fields = ['inter_arrival_time', 'packet_length', 'label']
                
                col1, col2 = st.columns(2)
                with col1:
                    st.write("*Required fields:*")
                    for field in required_fields:
                        if field in available_fields:
                            st.write(f"✅ `{field}`")
                        else:
                            st.write(f"❌ `{field}` (missing)")
                
                with col2:
                    st.write("*All available fields:*")
                    for field in available_fields:
                        st.write(f"- `{field}`")
            else:
                st.warning("❌ No fields found in measurement!")
        except Exception as e:
            st.error(f"Cannot fetch fields: {e}")
        
        # Debug sample data
        try:
            sample_df = query_api.query_data_frame(org=INFLUXDB_ORG, query=debug_query_sample)
            if isinstance(sample_df, list):
                sample_df = pd.concat(sample_df, ignore_index=True)
            
            if not sample_df.empty:
                st.write("**Sample Data Structure:**")
                st.write(f"Shape: {sample_df.shape}")
                st.write("Columns:", sample_df.columns.tolist())
                
                with st.expander("View Sample Data"):
                    st.dataframe(sample_df.head(10))
                
                # Check for field/value pattern
                if '_field' in sample_df.columns and '_value' in sample_df.columns:
                    st.info("✅ Data uses _field/_value pattern - pivot approach will work")
                    unique_fields = sample_df['_field'].unique()
                    st.write("Unique _field values:", unique_fields.tolist())
                else:
                    st.info("ℹ️ Data doesn't use _field/_value pattern - direct column approach needed")
            else:
                st.warning("❌ No sample data found!")
        except Exception as e:
            st.error(f"Cannot fetch sample data: {e}")
    
    except Exception as e:
        st.error(f"❌ Debug queries failed: {e}")
    
    st.divider()

# --- Main Data Processing ---
st.subheader("📊 Data Processing")

# Try multiple query approaches
df = None
approach_used = None

# Approach 1: Original pivot method
try:
    query_pivot = f'''
    from(bucket: "{INFLUXDB_BUCKET}")
      |> range(start: {time_window})
      |> filter(fn: (r) => r._measurement == "{INFLUXDB_MEASUREMENT}")
      |> filter(fn: (r) =>
          r._field == "inter_arrival_time" or
          r._field == "packet_length" or
          r._field == "label"
      )
      |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
      |> sort(columns: ["_time"])
      |> limit(n:200)
    '''
    
    df = query_api.query_data_frame(org=INFLUXDB_ORG, query=query_pivot)
    if isinstance(df, list):
        df = pd.concat(df, ignore_index=True)
    
    if not df.empty and "packet_length" in df.columns and "inter_arrival_time" in df.columns:
        approach_used = "Pivot Method"
        st.success(f"✅ Data loaded using {approach_used} - Found {len(df)} records")
    else:
        df = None
except Exception as e:
    if debug_mode:
        st.warning(f"Pivot approach failed: {e}")

# Approach 2: Flexible field matching
if df is None:
    try:
        query_flexible = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: {time_window})
          |> filter(fn: (r) => r._measurement == "{INFLUXDB_MEASUREMENT}")
          |> limit(n: 200)
        '''
        
        df_raw = query_api.query_data_frame(org=INFLUXDB_ORG, query=query_flexible)
        if isinstance(df_raw, list):
            df_raw = pd.concat(df_raw, ignore_index=True)
        
        if not df_raw.empty:
            # Try to find columns that match our needs
            field_mapping = {}
            
            # If using _field/_value pattern
            if '_field' in df_raw.columns and '_value' in df_raw.columns:
                available_fields = df_raw['_field'].unique()
                
                # Find matching fields with flexible naming
                for field in available_fields:
                    field_lower = field.lower()
                    if any(x in field_lower for x in ['arrival', 'inter', 'iat']):
                        field_mapping['inter_arrival_time'] = field
                    elif any(x in field_lower for x in ['length', 'size', 'len']):
                        field_mapping['packet_length'] = field
                    elif 'label' in field_lower:
                        field_mapping['label'] = field
                
                if field_mapping:
                    # Build dynamic pivot query
                    field_filters = [f'r._field == "{field}"' for field in field_mapping.values()]
                    
                    query_dynamic = f'''
                    from(bucket: "{INFLUXDB_BUCKET}")
                      |> range(start: {time_window})
                      |> filter(fn: (r) => r._measurement == "{INFLUXDB_MEASUREMENT}")
                      |> filter(fn: (r) => {" or ".join(field_filters)})
                      |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
                      |> sort(columns: ["_time"])
                      |> limit(n: 200)
                    '''
                    
                    df = query_api.query_data_frame(org=INFLUXDB_ORG, query=query_dynamic)
                    if isinstance(df, list):
                        df = pd.concat(df, ignore_index=True)
                    
                    # Rename columns to standard names
                    rename_map = {v: k for k, v in field_mapping.items()}
                    df = df.rename(columns=rename_map)
                    
                    approach_used = f"Dynamic Pivot (mapped: {field_mapping})"
            
            # Direct column approach
            else:
                # Look for direct columns
                for col in df_raw.columns:
                    col_lower = col.lower()
                    if any(x in col_lower for x in ['arrival', 'inter', 'iat']):
                        field_mapping['inter_arrival_time'] = col
                    elif any(x in col_lower for x in ['length', 'size', 'len']):
                        field_mapping['packet_length'] = col
                    elif 'label' in col_lower:
                        field_mapping['label'] = col
                
                if field_mapping:
                    df = df_raw.rename(columns={v: k for k, v in field_mapping.items()})
                    approach_used = f"Direct Columns (mapped: {field_mapping})"
            
            if df is not None and not df.empty:
                required_cols = ['inter_arrival_time', 'packet_length']
                if all(col in df.columns for col in required_cols):
                    st.success(f"✅ Data loaded using {approach_used} - Found {len(df)} records")
                else:
                    df = None
                    if debug_mode:
                        st.warning(f"Required columns not found after mapping. Available: {df.columns.tolist()}")
            
    except Exception as e:
        if debug_mode:
            st.warning(f"Flexible approach failed: {e}")

# Final check
if df is None or df.empty:
    st.error("❌ No valid data with required fields found in InfluxDB.")
    st.info("**Troubleshooting Tips:**")
    st.write("1. Check if data exists in the selected time range")
    st.write("2. Verify measurement name and field names")
    st.write("3. Ensure InfluxDB connection credentials are correct")
    st.write("4. Check if data is being written to the database")
    st.stop()

# --- Process Data for ML Model ---
try:
    # Clean and prepare data
    df = df.dropna(subset=['inter_arrival_time', 'packet_length'])
    
    if len(df) == 0:
        st.warning("⚠️ No valid data after removing null values.")
        st.stop()
    
    st.write(f"**Processing {len(df)} records with {approach_used}**")
    
    # Show data preview
    with st.expander("Preview Processed Data"):
        st.dataframe(df[['_time', 'inter_arrival_time', 'packet_length'] + (['label'] if 'label' in df.columns else [])].head(10))
    
    # Prepare payloads for API
    payloads = df[["inter_arrival_time", "packet_length"]].to_dict(orient="records")
    predictions = []
    
    # Progress bar for API calls
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    with st.spinner("🔍 Running anomaly detection..."):
        for i, (index, row) in enumerate(df.iterrows()):
            try:
                payload = {
                    "inter_arrival_time": float(row["inter_arrival_time"]),
                    "packet_length": float(row["packet_length"])
                }
                
                response = requests.post(API_URL, json=payload, timeout=10)
                response.raise_for_status()
                result = response.json()
                
                # Add metadata
                result.update({
                    "timestamp": row["_time"],
                    "inter_arrival_time": payload["inter_arrival_time"],
                    "packet_length": payload["packet_length"],
                    "label": row.get("label", None)
                })
                predictions.append(result)
                
                # Update progress
                progress = (i + 1) / len(df)
                progress_bar.progress(progress)
                status_text.text(f"Processed {i + 1}/{len(df)} records")
                
            except requests.exceptions.RequestException as e:
                if debug_mode:
                    st.error(f"API error at index {index}: {e}")
                continue
            except Exception as e:
                if debug_mode:
                    st.warning(f"Processing error at index {index}: {e}")
                continue
    
    progress_bar.empty()
    status_text.empty()
    
    if not predictions:
        st.error("❌ No predictions returned from the model.")
        st.stop()
    
    # Convert to DataFrame
    df_pred = pd.DataFrame(predictions)
    df_pred["timestamp"] = pd.to_datetime(df_pred["timestamp"])
    
    st.success(f"✅ Successfully processed {len(predictions)} predictions")
    
    # --- Model Metrics ---
    if 'label' in df_pred.columns and df_pred['label'].notna().any():
        st.subheader("📊 Model Metrics")
        valid = df_pred.dropna(subset=["label", "anomaly"])
        
        if not valid.empty and len(valid) > 0:
            y_true = valid["label"].astype(int)
            y_pred = valid["anomaly"].astype(int)
            
            # Metrics
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Accuracy", f"{accuracy_score(y_true, y_pred)*100:.2f}%")
            col2.metric("Precision", f"{precision_score(y_true, y_pred, zero_division=0)*100:.2f}%")
            col3.metric("Recall", f"{recall_score(y_true, y_pred, zero_division=0)*100:.2f}%")
            col4.metric("F1 Score", f"{f1_score(y_true, y_pred, zero_division=0)*100:.2f}%")
            
            # Confusion Matrix
            try:
                cm = confusion_matrix(y_true, y_pred)
                fig_cm = ff.create_annotated_heatmap(
                    z=cm,
                    x=["Pred Normal", "Pred Attack"],
                    y=["Actual Normal", "Actual Attack"],
                    annotation_text=cm.astype(str),
                    colorscale="Blues"
                )
                fig_cm.update_layout(title="Confusion Matrix")
                st.plotly_chart(fig_cm, use_container_width=True)
            except Exception as e:
                if debug_mode:
                    st.error(f"Confusion matrix error: {e}")
        else:
            st.info("ℹ️ No valid labels found for metric calculation")
    
    # --- Visualizations ---
    st.subheader("📈 Time Series Analysis")
    
    # Reconstruction Error Over Time
    fig_error = px.line(
        df_pred, 
        x="timestamp", 
        y="reconstruction_error", 
        color="anomaly",
        color_discrete_map={0: "blue", 1: "red"},
        title="Reconstruction Error Over Time",
        labels={
            "reconstruction_error": "Reconstruction Error",
            "timestamp": "Time",
            "anomaly": "Anomaly"
        }
    )
    fig_error.add_hline(
        y=thresh, 
        line_dash="dash", 
        line_color="green", 
        annotation_text=f"Threshold ({thresh})"
    )
    st.plotly_chart(fig_error, use_container_width=True)
    
    # Feature Distribution
    col1, col2 = st.columns(2)
    
    with col1:
        fig_iat = px.histogram(
            df_pred, 
            x="inter_arrival_time", 
            color="anomaly",
            title="Inter-Arrival Time Distribution",
            nbins=30
        )
        st.plotly_chart(fig_iat, use_container_width=True)
    
    with col2:
        fig_plen = px.histogram(
            df_pred, 
            x="packet_length", 
            color="anomaly",
            title="Packet Length Distribution",
            nbins=30
        )
        st.plotly_chart(fig_plen, use_container_width=True)
    
    # Scatter Plot
    fig_scatter = px.scatter(
        df_pred,
        x="inter_arrival_time",
        y="packet_length",
        color="anomaly",
        size="reconstruction_error",
        title="Feature Space Analysis",
        color_discrete_map={0: "blue", 1: "red"}
    )
    st.plotly_chart(fig_scatter, use_container_width=True)
    
    # --- Summary Statistics ---
    st.subheader("📋 Summary Statistics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Anomaly Detection Summary:**")
        anomaly_counts = df_pred['anomaly'].value_counts()
        total_count = len(df_pred)
        normal_count = anomaly_counts.get(0, 0)
        anomaly_count = anomaly_counts.get(1, 0)
        
        st.metric("Total Records", total_count)
        st.metric("Normal Traffic", f"{normal_count} ({normal_count/total_count*100:.1f}%)")
        st.metric("Anomalous Traffic", f"{anomaly_count} ({anomaly_count/total_count*100:.1f}%)")
    
    with col2:
        st.write("**Reconstruction Error Stats:**")
        error_stats = df_pred['reconstruction_error'].describe()
        st.metric("Mean Error", f"{error_stats['mean']:.4f}")
        st.metric("Max Error", f"{error_stats['max']:.4f}")
        st.metric("Std Error", f"{error_stats['std']:.4f}")
    
    # --- Data Table ---
    st.subheader("🔍 Detailed Results")
    
    # Filter options
    col1, col2 = st.columns(2)
    with col1:
        show_anomalies_only = st.checkbox("Show Anomalies Only", value=False)
    with col2:
        sort_by_error = st.checkbox("Sort by Reconstruction Error", value=True)
    
    # Filter and sort data
    display_df = df_pred.copy()
    if show_anomalies_only:
        display_df = display_df[display_df['anomaly'] == 1]
    
    if sort_by_error:
        display_df = display_df.sort_values('reconstruction_error', ascending=False)
    
    # Display table
    st.dataframe(
        display_df[[
            "timestamp", 
            "inter_arrival_time", 
            "packet_length", 
            "reconstruction_error", 
            "anomaly"
        ] + (["label"] if "label" in display_df.columns else [])],
        use_container_width=True
    )
    
    # Download option
    csv = df_pred.to_csv(index=False)
    st.download_button(
        label="📥 Download Results as CSV",
        data=csv,
        file_name=f"dos_detection_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv"
    )

except Exception as e:
    st.error(f"❌ Failed to process data: {e}")
    if debug_mode:
        st.exception(e)
