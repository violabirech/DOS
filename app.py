import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from influxdb_client import InfluxDBClient
from datetime import datetime, timedelta
 --- InfluxDB Configuration ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "6gjE97dCC24hgOgWNmRXPqOS0pfc0pMSYeh5psL8e5u2T8jGeV1F17CU-U1z05if0jfTEmPRW9twNPSXN09SRQ=="
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime_dns"
# Validate required environment variables
if not all([INFLUXDB_URL, INFLUXDB_TOKEN, INFLUXDB_ORG, INFLUXDB_BUCKET]):
    st.error("❌ Missing required environment variables. Please set INFLUXDB_URL, INFLUXDB_TOKEN, INFLUXDB_ORG, and INFLUXDB_BUCKET")
    st.stop()

# Page configuration
st.set_page_config(
    page_title="DOS Attack Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #ff6b6b;
    }
    .alert-high {
        background-color: #ffe6e6;
        border-left: 4px solid #ff4444;
        padding: 1rem;
        border-radius: 0.5rem;
    }
    .alert-medium {
        background-color: #fff4e6;
        border-left: 4px solid #ff8c00;
        padding: 1rem;
        border-radius: 0.5rem;
    }
    .alert-low {
        background-color: #e6ffe6;
        border-left: 4px solid #4CAF50;
        padding: 1rem;
        border-radius: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_data(ttl=30)  # Cache for 30 seconds
def get_influxdb_data(time_range="1h"):
    """Fetch network traffic data from InfluxDB"""
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        query_api = client.query_api()
        
        # Query for DNS traffic data
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
        |> range(start: -{time_range})
        |> filter(fn: (r) => r["_measurement"] == "network_traffic")
        |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
        |> sort(columns: ["_time"])
        '''
        
        result = query_api.query_data_frame(query)
        client.close()
        
        if not result.empty:
            # Convert timestamp to datetime
            result['_time'] = pd.to_datetime(result['_time'])
            return result
        else:
            return pd.DataFrame()
            
    except Exception as e:
        st.error(f"Error connecting to InfluxDB: {str(e)}")
        return pd.DataFrame()

def detect_dns_dos_patterns(df):
    """Analyze DNS traffic patterns for DOS attack indicators"""
    if df.empty:
        return {}
    
    # Calculate metrics
    current_time = datetime.now()
    last_5min = current_time - timedelta(minutes=5)
    last_1min = current_time - timedelta(minutes=1)
    
    # Convert to timezone-aware datetime for comparison
    df['_time'] = pd.to_datetime(df['_time']).dt.tz_localize(None)
    
    recent_5min = df[df['_time'] >= last_5min]
    recent_1min = df[df['_time'] >= last_1min]
    
    # DNS DOS detection metrics
    metrics = {
        'total_queries': len(df),
        'queries_last_5min': len(recent_5min),
        'queries_last_1min': len(recent_1min),
        'avg_queries_per_min': len(df) / max(1, (df['_time'].max() - df['_time'].min()).total_seconds() / 60),
        'unique_source_ips': df['source_ip'].nunique() if 'source_ip' in df.columns else 0,
        'unique_domains': df['query_name'].nunique() if 'query_name' in df.columns else 0,
        'top_source_ips': df['source_ip'].value_counts().head(10).to_dict() if 'source_ip' in df.columns else {},
        'top_queried_domains': df['query_name'].value_counts().head(10).to_dict() if 'query_name' in df.columns else {},
        'query_types': df['query_type'].value_counts().to_dict() if 'query_type' in df.columns else {},
        'response_codes': df['response_code'].value_counts().to_dict() if 'response_code' in df.columns else {},
        'failed_queries': len(df[df['response_code'] == 'NXDOMAIN']) if 'response_code' in df.columns else 0
    }
    
    # DNS DOS Alert levels
    queries_per_min = metrics['queries_last_1min']
    failed_ratio = metrics['failed_queries'] / max(1, metrics['total_queries'])
    
    if queries_per_min > 5000 or failed_ratio > 0.8:
        metrics['alert_level'] = 'HIGH'
        metrics['alert_message'] = f"🚨 HIGH ALERT: {queries_per_min} DNS queries/min, {failed_ratio:.1%} failed"
    elif queries_per_min > 2000 or failed_ratio > 0.5:
        metrics['alert_level'] = 'MEDIUM'
        metrics['alert_message'] = f"⚠️ MEDIUM ALERT: {queries_per_min} DNS queries/min, {failed_ratio:.1%} failed"
    else:
        metrics['alert_level'] = 'LOW'
        metrics['alert_message'] = f"✅ Normal DNS traffic: {queries_per_min} queries/min"
    
    return metrics

def create_dns_timeline(df):
    """Create DNS queries timeline chart"""
    if df.empty:
        return go.Figure()
    
    # Resample data to show queries per minute
    df_resampled = df.set_index('_time').resample('1T').size().reset_index()
    df_resampled.columns = ['time', 'queries']
    
    fig = px.line(df_resampled, x='time', y='queries', 
                  title='DNS Queries Over Time (Queries per Minute)',
                  labels={'queries': 'DNS Queries per Minute', 'time': 'Time'})
    
    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="DNS Queries per Minute",
        hovermode='x unified'
    )
    
    return fig': 'Requests per Minute', 'time': 'Time'})
    
    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Requests per Minute",
        hovermode='x unified'
    )
    
    return fig

def create_source_ip_chart(top_ips):
    """Create source IP distribution chart"""
    if not top_ips:
        return go.Figure()
    
    ips = list(top_ips.keys())
    counts = list(top_ips.values())
    
    fig = px.bar(x=ips, y=counts, 
                title='Top Source IPs',
                labels={'x': 'Source IP', 'y': 'Request Count'})
    
    fig.update_layout(xaxis_tickangle=-45)
    return fig

def create_response_code_chart(response_codes):
    """Create response code distribution chart"""
    if not response_codes:
        return go.Figure()
    
    codes = list(response_codes.keys())
    counts = list(response_codes.values())
    
    fig = px.pie(values=counts, names=codes, 
                title='HTTP Response Code Distribution')
    
    return fig

# Main Dashboard
def main():
    st.title("🛡️ DNS DOS Attack Detection Dashboard")
    st.markdown("Real-time monitoring of DNS traffic for DOS attack patterns")
    
    # Sidebar controls
    st.sidebar.header("Dashboard Controls")
    time_range = st.sidebar.selectbox(
        "Select Time Range",
        ["5m", "15m", "1h", "6h", "24h"],
        index=2
    )
    
    auto_refresh = st.sidebar.checkbox("Auto Refresh (30s)", value=False)
    
    if st.sidebar.button("🔄 Refresh Data") or auto_refresh:
        st.rerun()
    
    # Fetch data
    with st.spinner("Loading network traffic data..."):
        df = get_influxdb_data(time_range)
    
    if df.empty:
        st.warning("No DNS data available. Please check your InfluxDB connection and ensure data is being written to the 'network_traffic' measurement.")
        st.info("Expected DNS fields: source_ip, query_name, query_type, response_code, timestamp")
        return
    
    # Analyze for DNS DOS patterns
    metrics = detect_dns_dos_patterns(df)
    
    # Alert Section
    st.header("🚨 Security Alerts")
    
    if metrics['alert_level'] == 'HIGH':
        st.markdown(f'<div class="alert-high">{metrics["alert_message"]}</div>', 
                   unsafe_allow_html=True)
    elif metrics['alert_level'] == 'MEDIUM':
        st.markdown(f'<div class="alert-medium">{metrics["alert_message"]}</div>', 
                   unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="alert-low">{metrics["alert_message"]}</div>', 
                   unsafe_allow_html=True)
    
    # Metrics Overview
    st.header("📊 DNS Traffic Metrics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total DNS Queries", metrics.get('total_queries', 0))
    
    with col2:
        st.metric("Queries (Last 5min)", metrics.get('queries_last_5min', 0))
    
    with col3:
        st.metric("Unique Source IPs", metrics.get('unique_source_ips', 0))
    
    with col4:
        st.metric("Unique Domains", metrics.get('unique_domains', 0))
    
    # Additional DNS metrics
    col5, col6, col7, col8 = st.columns(4)
    
    with col5:
        st.metric("Avg Queries/Min", f"{metrics.get('avg_queries_per_min', 0):.1f}")
    
    with col6:
        st.metric("Failed Queries", metrics.get('failed_queries', 0))
    
    with col7:
        failure_rate = metrics.get('failed_queries', 0) / max(1, metrics.get('total_queries', 1))
        st.metric("Failure Rate", f"{failure_rate:.1%}")
    
    with col8:
        st.metric("Query Types", len(metrics.get('query_types', {})))
    
    # Charts
    st.header("📈 DNS Traffic Analysis")
    
    # DNS queries timeline
    st.plotly_chart(create_dns_timeline(df), use_container_width=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Top source IPs
        if metrics.get('top_source_ips'):
            st.plotly_chart(create_source_ip_chart(metrics['top_source_ips']), 
                          use_container_width=True)
    
    with col2:
        # Top queried domains
        if metrics.get('top_queried_domains'):
            fig = px.bar(x=list(metrics['top_queried_domains'].keys())[:10], 
                        y=list(metrics['top_queried_domains'].values())[:10],
                        title='Top Queried Domains',
                        labels={'x': 'Domain', 'y': 'Query Count'})
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
    
    # Additional DNS-specific charts
    col3, col4 = st.columns(2)
    
    with col3:
        # Query types distribution
        if metrics.get('query_types'):
            st.plotly_chart(create_response_code_chart(metrics['query_types']), 
                          use_container_width=True)
    
    with col4:
        # Response codes
        if metrics.get('response_codes'):
            st.plotly_chart(create_response_code_chart(metrics['response_codes']), 
                          use_container_width=True)
    
    # Detailed Data Table
    with st.expander("📋 Raw DNS Traffic Data"):
        st.dataframe(df.tail(100))  # Show last 100 records
    
    # DNS DOS Detection Rules
    with st.expander("🔍 DNS DOS Detection Rules"):
        st.markdown("""
        **DNS Alert Thresholds:**
        - 🔴 **HIGH**: > 5000 DNS queries per minute OR > 80% failed queries
        - 🟡 **MEDIUM**: > 2000 DNS queries per minute OR > 50% failed queries
        - 🟢 **LOW**: < 2000 DNS queries per minute
        
        **DNS Attack Patterns:**
        - DNS amplification attacks (high query volume)
        - DNS flooding (excessive queries from few IPs)
        - Random subdomain attacks (high NXDOMAIN responses)
        - Query type anomalies (unusual record types)
        - Recursive query abuse
        
        **Key Indicators:**
        - Sudden spikes in query volume
        - High concentration from few source IPs
        - Excessive NXDOMAIN responses
        - Unusual query patterns or types
        - High bandwidth DNS traffic
        """)
    
    # DNS Security Tips
    with st.expander("💡 DNS Security Recommendations"):
        st.markdown("""
        **Mitigation Strategies:**
        - Rate limiting per source IP
        - DNS response rate limiting (RRL)
        - Block recursive queries from external sources
        - Implement DNS filtering and blacklists
        - Monitor for subdomain enumeration
        - Use DNS firewalls and threat intelligence
        - Deploy anycast DNS for load distribution
        """)
    
    # Auto-refresh
    if auto_refresh:
        time.sleep(30)
        st.rerun()

if __name__ == "__main__":
    main()