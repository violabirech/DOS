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
time_window = st.sidebar.selectbox("Time Range", ["-5m", "-15m", "-1h", "-6h", "-12h", "-1d", "-7d", "-30d"], index=2)
thresh = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
debug_mode = st.sidebar.checkbox("Show Debug Info", value=True)

# Add configuration override in sidebar
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
st.title("🚀 DoS Anomaly Detection Dashboard")

# --- Enhanced Diagnostics ---
st.subheader("🔧 Enhanced Diagnostics")

# Test connection first
try:
    client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
    query_api = client.query_api()
    
    # Test basic connection
    st.write("**Connection Test:**")
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("✅ InfluxDB client created successfully")
        st.write(f"🔗 URL: `{INFLUXDB_URL}`")
        st.write(f"🏢 Organization: `{INFLUXDB_ORG}`")
        st.write(f"🪣 Bucket: `{INFLUXDB_BUCKET}`")
        st.write(f"📊 Measurement: `{INFLUXDB_MEASUREMENT}`")
        st.write(f"⏰ Time Range: `{time_window}`")

    # Test 1: Check if any data exists in the bucket (any measurement, any time)
    st.write("**Step 1: Check if bucket has ANY data**")
    try:
        test_query_any = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: -30d)
          |> limit(n: 1)
        '''
        
        any_data = query_api.query_data_frame(org=INFLUXDB_ORG, query=test_query_any)
        if isinstance(any_data, list) and any_data:
            any_data = pd.concat(any_data, ignore_index=True)
        
        if any_data is not None and not any_data.empty:
            st.success(f"✅ Bucket contains data! Found {len(any_data)} records")
            if debug_mode:
                st.json({
                    "columns": any_data.columns.tolist(),
                    "shape": any_data.shape,
                    "sample_data": any_data.head(3).to_dict('records') if len(any_data) > 0 else []
                })
        else:
            st.error("❌ Bucket is completely empty - no data found in last 30 days")
            st.info("**Possible issues:**")
            st.write("- Data hasn't been written to InfluxDB yet")
            st.write("- Wrong bucket name")
            st.write("- Authentication issues")
            st.stop()
            
    except Exception as e:
        st.error(f"❌ Cannot access bucket: {e}")
        st.info("**Possible issues:**")
        st.write("- Invalid token or permissions")
        st.write("- Wrong organization name")
        st.write("- Network connectivity issues")
        st.stop()

    # Test 2: List all measurements in the bucket
    st.write("**Step 2: List all measurements in bucket**")
    try:
        measurements_query = f'''
        import "influxdata/influxdb/schema"
        schema.measurements(bucket: "{INFLUXDB_BUCKET}")
        '''
        
        measurements_df = query_api.query_data_frame(org=INFLUXDB_ORG, query=measurements_query)
        if isinstance(measurements_df, list) and measurements_df:
            measurements_df = pd.concat(measurements_df, ignore_index=True)
        
        if measurements_df is not None and not measurements_df.empty and '_value' in measurements_df.columns:
            available_measurements = measurements_df['_value'].unique().tolist()
            st.write(f"**Available measurements ({len(available_measurements)}):**")
            
            for i, measurement in enumerate(available_measurements, 1):
                if measurement == INFLUXDB_MEASUREMENT:
                    st.write(f"{i}. ✅ `{measurement}` (selected)")
                else:
                    st.write(f"{i}. 📊 `{measurement}`")
                    
            if INFLUXDB_MEASUREMENT not in available_measurements:
                st.warning(f"⚠️ Your measurement '{INFLUXDB_MEASUREMENT}' not found!")
                st.info("Try using one of the available measurements above in the sidebar.")
        else:
            st.warning("❌ No measurements found using schema.measurements()")
            
    except Exception as e:
        st.warning(f"Schema query failed: {e}")
        
        # Fallback: try to find measurements manually
        try:
            fallback_query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: -30d)
              |> group()
              |> distinct(column: "_measurement")
              |> limit(n: 100)
            '''
            
            fallback_df = query_api.query_data_frame(org=INFLUXDB_ORG, query=fallback_query)
            if isinstance(fallback_df, list) and fallback_df:
                fallback_df = pd.concat(fallback_df, ignore_index=True)
            
            if fallback_df is not None and not fallback_df.empty and '_value' in fallback_df.columns:
                measurements = fallback_df['_value'].unique().tolist()
                st.write(f"**Found measurements (fallback method):**")
                for measurement in measurements:
                    if measurement == INFLUXDB_MEASUREMENT:
                        st.write(f"✅ `{measurement}` (selected)")
                    else:
                        st.write(f"📊 `{measurement}`")
            else:
                st.error("❌ No measurements found with fallback method either")
                
        except Exception as e2:
            st.error(f"❌ Fallback measurement query also failed: {e2}")

    # Test 3: Check specific measurement
    st.write(f"**Step 3: Check measurement '{INFLUXDB_MEASUREMENT}'**")
    try:
        measurement_query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "{INFLUXDB_MEASUREMENT}")
          |> limit(n: 10)
        '''
        
        measurement_data = query_api.query_data_frame(org=INFLUXDB_ORG, query=measurement_query)
        if isinstance(measurement_data, list) and measurement_data:
            measurement_data = pd.concat(measurement_data, ignore_index=True)
        
        if measurement_data is not None and not measurement_data.empty:
            st.success(f"✅ Found {len(measurement_data)} records in measurement '{INFLUXDB_MEASUREMENT}'")
            
            # Show time range of data
            if '_time' in measurement_data.columns:
                min_time = measurement_data['_time'].min()
                max_time = measurement_data['_time'].max()
                st.write(f"📅 Data time range: {min_time} to {max_time}")
                
                # Check if data exists in selected time window
                from datetime import datetime, timedelta
                now = datetime.now()
                time_deltas = {
                    '-5m': timedelta(minutes=5),
                    '-15m': timedelta(minutes=15),
                    '-1h': timedelta(hours=1),
                    '-6h': timedelta(hours=6),
                    '-12h': timedelta(hours=12),
                    '-1d': timedelta(days=1),
                    '-7d': timedelta(days=7),
                    '-30d': timedelta(days=30)
                }
                
                if time_window in time_deltas:
                    cutoff_time = now - time_deltas[time_window]
                    recent_data = measurement_data[pd.to_datetime(measurement_data['_time']) >= cutoff_time]
                    
                    if not recent_data.empty:
                        st.success(f"✅ Found {len(recent_data)} records in selected time range ({time_window})")
                    else:
                        st.warning(f"⚠️ No data found in selected time range ({time_window})")
                        st.info(f"Most recent data is from: {max_time}")
                        st.info("Try selecting a longer time range in the sidebar")
            
            # Show available fields
            if '_field' in measurement_data.columns:
                available_fields = measurement_data['_field'].unique().tolist()
                st.write(f"**Available fields ({len(available_fields)}):**")
                
                required_fields = ['inter_arrival_time', 'packet_length', 'label']
                for field in available_fields:
                    if field in required_fields:
                        st.write(f"✅ `{field}` (required)")
                    else:
                        st.write(f"📊 `{field}`")
                
                missing_fields = [f for f in required_fields if f not in available_fields]
                if missing_fields:
                    st.warning(f"⚠️ Missing required fields: {missing_fields}")
            
            if debug_mode:
                with st.expander("🔍 Sample Data from Measurement"):
                    st.dataframe(measurement_data.head(10))
                    
        else:
            st.error(f"❌ No data found in measurement '{INFLUXDB_MEASUREMENT}'")
            st.info("The measurement name might be incorrect, or no data has been written to it.")
            
    except Exception as e:
        st.error(f"❌ Error checking measurement: {e}")

    # Test 4: Try the actual query with selected time range
    st.write(f"**Step 4: Test query with selected time range ({time_window})**")
    try:
        actual_query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: {time_window})
          |> filter(fn: (r) => r._measurement == "{INFLUXDB_MEASUREMENT}")
          |> limit(n: 50)
        '''
        
        actual_data = query_api.query_data_frame(org=INFLUXDB_ORG, query=actual_query)
        if isinstance(actual_data, list) and actual_data:
            actual_data = pd.concat(actual_data, ignore_index=True)
        
        if actual_data is not None and not actual_data.empty:
            st.success(f"✅ Query successful! Found {len(actual_data)} records in {time_window}")
            
            # Now try to process the data
            st.subheader("📊 Data Processing")
            
            # Check for required fields
            if '_field' in actual_data.columns and '_value' in actual_data.columns:
                available_fields = actual_data['_field'].unique().tolist()
                required_fields = ['inter_arrival_time', 'packet_length']
                
                found_fields = [f for f in required_fields if f in available_fields]
                st.write(f"Required fields found: {found_fields}")
                
                if len(found_fields) >= 2:  # At least 2 required fields
                    # Try pivot approach
                    pivot_query = f'''
                    from(bucket: "{INFLUXDB_BUCKET}")
                      |> range(start: {time_window})
                      |> filter(fn: (r) => r._measurement == "{INFLUXDB_MEASUREMENT}")
                      |> filter(fn: (r) => {" or ".join([f'r._field == "{f}"' for f in found_fields])})
                      |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
                      |> sort(columns: ["_time"])
                      |> limit(n: 200)
                    '''
                    
                    pivot_data = query_api.query_data_frame(org=INFLUXDB_ORG, query=pivot_query)
                    if isinstance(pivot_data, list) and pivot_data:
                        pivot_data = pd.concat(pivot_data, ignore_index=True)
                    
                    if pivot_data is not None and not pivot_data.empty:
                        st.success(f"✅ Pivot successful! Processing {len(pivot_data)} records")
                        
                        # Continue with ML processing
                        df = pivot_data.dropna(subset=found_fields)
                        
                        if len(df) > 0:
                            # Prepare for API calls
                            payloads = df[found_fields].to_dict(orient="records")
                            predictions = []
                            
                            progress_bar = st.progress(0)
                            status_text = st.empty()
                            
                            with st.spinner("🔍 Running anomaly detection..."):
                                for i, (index, row) in enumerate(df.iterrows()):
                                    try:
                                        payload = {
                                            "inter_arrival_time": float(row[found_fields[0]] if found_fields[0] in row else row["inter_arrival_time"]),
                                            "packet_length": float(row[found_fields[1]] if found_fields[1] in row and len(found_fields) > 1 else row["packet_length"])
                                        }
                                        
                                        response = requests.post(API_URL, json=payload, timeout=10)
                                        response.raise_for_status()
                                        result = response.json()
                                        
                                        result.update({
                                            "timestamp": row["_time"],
                                            "inter_arrival_time": payload["inter_arrival_time"],
                                            "packet_length": payload["packet_length"],
                                            "label": row.get("label", None)
                                        })
                                        predictions.append(result)
                                        
                                        progress = (i + 1) / len(df)
                                        progress_bar.progress(progress)
                                        status_text.text(f"Processed {i + 1}/{len(df)} records")
                                        
                                        # Limit for demo
                                        if i >= 49:  # Process max 50 records
                                            break
                                            
                                    except Exception as e:
                                        if debug_mode:
                                            st.warning(f"API error at {i}: {e}")
                                        continue
                            
                            progress_bar.empty()
                            status_text.empty()
                            
                            if predictions:
                                df_pred = pd.DataFrame(predictions)
                                df_pred["timestamp"] = pd.to_datetime(df_pred["timestamp"])
                                
                                st.success(f"✅ Successfully processed {len(predictions)} predictions")
                                
                                # Show results
                                st.subheader("📈 Results")
                                
                                # Quick stats
                                col1, col2, col3 = st.columns(3)
                                anomaly_count = df_pred['anomaly'].sum()
                                normal_count = len(df_pred) - anomaly_count
                                
                                col1.metric("Total Records", len(df_pred))
                                col2.metric("Normal", normal_count)
                                col3.metric("Anomalies", anomaly_count)
                                
                                # Simple plot
                                fig = px.line(
                                    df_pred, 
                                    x="timestamp", 
                                    y="reconstruction_error",
                                    color="anomaly",
                                    title="Anomaly Detection Results"
                                )
                                fig.add_hline(y=thresh, line_dash="dash", line_color="green")
                                st.plotly_chart(fig, use_container_width=True)
                                
                                # Data table
                                st.subheader("📋 Data Table")
                                st.dataframe(df_pred[[
                                    "timestamp", 
                                    "inter_arrival_time", 
                                    "packet_length", 
                                    "reconstruction_error", 
                                    "anomaly"
                                ]])
                                
                            else:
                                st.error("❌ No predictions returned from API")
                        else:
                            st.error("❌ No valid data after removing null values")
                    else:
                        st.error("❌ Pivot operation failed")
                else:
                    st.error(f"❌ Insufficient required fields. Found: {found_fields}")
            else:
                st.warning("❌ Data doesn't follow _field/_value structure")
                
        else:
            st.error(f"❌ No data found in selected time range ({time_window})")
            st.info("Try selecting a longer time range or check if data is being written to InfluxDB")
            
    except Exception as e:
        st.error(f"❌ Query failed: {e}")

except Exception as e:
    st.error(f"❌ Failed to connect to InfluxDB: {e}")
    st.info("Check your connection details and token permissions")

st.markdown("---")
st.write("**Debug complete.** Use the information above to identify and fix the data issues.")
