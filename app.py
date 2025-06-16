import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

# Graceful dependency handling to prevent ModuleNotFoundError
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    MATPLOTLIB_AVAILABLE = True
    st.success("✅ Matplotlib and Seaborn loaded successfully")
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    st.warning("⚠️ Matplotlib/Seaborn not available. Using fallback visualizations.")

try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
    st.success("✅ Plotly loaded successfully")
except ImportError:
    PLOTLY_AVAILABLE = False
    st.warning("⚠️ Plotly not available. Using Streamlit's built-in charts.")

# Set page configuration
st.set_page_config(
    page_title="Data Analysis Dashboard",
    page_icon="📊",
    layout="wide"
)

st.title("📊 Robust Data Analysis Dashboard")
st.markdown("**Handles both ModuleNotFoundError and KeyError issues gracefully**")

def safe_column_access(df, column_name, operation="mean", default_value=None):
    """
    Safely access DataFrame columns to prevent KeyError
    This solves your original inter_arrival_time KeyError issue
    """
    try:
        if column_name in df.columns:
            column_data = df[column_name]
            
            if operation == "mean":
                # This is the exact calculation that was failing before
                result = column_data.replace(0, np.nan).mean()
                return result if not pd.isna(result) else default_value
            elif operation == "std":
                return column_data.std()
            elif operation == "count":
                return len(column_data)
            else:
                return column_data
        else:
            st.error(f"Column '{column_name}' not found in DataFrame")
            return default_value
    except Exception as e:
        st.error(f"Error accessing column '{column_name}': {str(e)}")
        return default_value

def generate_sample_data(num_rows=1000):
    """Generate sample data including the problematic inter_arrival_time column"""
    np.random.seed(42)
    
    data = {
        'timestamp': pd.date_range(start='2024-01-01', periods=num_rows, freq='1min'),
        'inter_arrival_time': np.random.exponential(2.0, num_rows),
        'request_count': np.random.poisson(5, num_rows),
        'response_time': np.random.gamma(2, 2, num_rows),
        'server_load': np.random.beta(2, 5, num_rows) * 100,
        'error_rate': np.random.uniform(0, 0.1, num_rows)
    }
    
    # Add some zeros to demonstrate the replace(0, np.nan) functionality
    zero_indices = np.random.choice(num_rows, size=int(num_rows * 0.1), replace=False)
    for idx in zero_indices:
        data['inter_arrival_time'][idx] = 0
    
    return pd.DataFrame(data)

# Sidebar for data input
st.sidebar.header("Data Input")
data_source = st.sidebar.selectbox(
    "Choose data source:",
    ["Generate Sample Data", "Upload CSV File"]
)

df = None

if data_source == "Generate Sample Data":
    num_rows = st.sidebar.slider("Number of rows:", 100, 2000, 1000)
    if st.sidebar.button("Generate Data"):
        df = generate_sample_data(num_rows)
        st.success(f"Generated {len(df)} rows of sample data")

elif data_source == "Upload CSV File":
    uploaded_file = st.sidebar.file_uploader("Choose CSV file", type="csv")
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            # Standardize column names to prevent common KeyError issues
            df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
            st.success(f"Loaded {len(df)} rows from {uploaded_file.name}")
        except Exception as e:
            st.error(f"Error loading file: {str(e)}")

# Main analysis section
if df is not None:
    st.header("📋 Data Overview")
    
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Available Columns:**", df.columns.tolist())
        st.write("**Data Shape:**", df.shape)
    with col2:
        st.write("**Data Types:**")
        st.write(df.dtypes)
    
    st.subheader("Sample Data")
    st.dataframe(df.head(), use_container_width=True)
    
    # Inter-arrival time analysis - this solves your original KeyError
    st.header("⏱️ Inter-Arrival Time Analysis")
    target_column = "inter_arrival_time"
    
    if target_column in df.columns:
        st.success(f"✅ Column '{target_column}' found!")
        
        # Perform the calculation that was causing your KeyError
        mean_arrival = safe_column_access(df, target_column, "mean", 0)
        std_arrival = safe_column_access(df, target_column, "std", 0)
        count_nonzero = len(df[df[target_column] > 0])
        
        # Display results
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Mean Inter-arrival Time", f"{mean_arrival:.4f}s")
        with col2:
            st.metric("Standard Deviation", f"{std_arrival:.4f}s")
        with col3:
            st.metric("Non-zero Values", count_nonzero)
        
        # Show the exact calculation that was failing
        st.subheader("🔧 Original Calculation (Now Fixed)")
        st.code(f"""
# This line was causing your KeyError:
mean_arrival = df["inter_arrival_time"].replace(0, np.nan).mean()

# Result: {mean_arrival:.6f} seconds
""")
        
        # Visualization with fallback handling
        st.subheader("📊 Visualizations")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Distribution of Inter-arrival Times**")
            filtered_data = df[df[target_column] > 0][target_column]
            
            if MATPLOTLIB_AVAILABLE and len(filtered_data) > 0:
                fig, ax = plt.subplots(figsize=(8, 5))
                ax.hist(filtered_data, bins=30, alpha=0.7, color='skyblue', edgecolor='black')
                ax.set_xlabel('Inter-arrival Time (seconds)')
                ax.set_ylabel('Frequency')
                ax.set_title('Distribution (excluding zeros)')
                st.pyplot(fig)
            else:
                # Fallback to Streamlit's built-in chart
                st.bar_chart(filtered_data.value_counts().sort_index().head(20))
        
        with col2:
            st.write("**Time Series Plot**")
            display_data = df[target_column].head(100)
            
            if PLOTLY_AVAILABLE:
                fig = px.line(x=range(len(display_data)), y=display_data,
                             title='Inter-arrival Time Over Time',
                             labels={'x': 'Sample Index', 'y': 'Inter-arrival Time'})
                st.plotly_chart(fig, use_container_width=True)
            else:
                # Fallback to Streamlit's line chart
                st.line_chart(display_data)
    
    else:
        st.error(f"❌ Column '{target_column}' not found!")
        st.write("**Available columns:**", df.columns.tolist())
        
        # Suggest similar columns
        similar_cols = [col for col in df.columns if 'time' in col.lower() or 'arrival' in col.lower()]
        if similar_cols:
            st.info(f"💡 Similar columns found: {similar_cols}")
    
    # Additional analysis
    st.header("📈 Statistical Summary")
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) > 0:
        st.dataframe(df[numeric_cols].describe(), use_container_width=True)
    
    # Export functionality
    st.header("💾 Export Data")
    if st.button("Download Processed Data"):
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"processed_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

else:
    st.info("👆 Please select a data source from the sidebar to begin analysis.")
    
    st.markdown("""
    ## 🚀 What This App Solves
    
    **ModuleNotFoundError Prevention:**
    - Graceful handling of missing visualization libraries
    - Fallback to Streamlit's built-in charts when external libraries unavailable
    - Clear status messages about which dependencies are loaded
    
    **KeyError Prevention:**
    - Safe column access functions that check existence before accessing
    - Comprehensive error handling with helpful suggestions
    - Standardized column naming to prevent common issues
    
    **Production Ready:**
    - Works with minimal dependencies (just streamlit, pandas, numpy)
    - Enhanced features when full dependencies are available
    - Professional error handling throughout
    """)

# Footer showing dependency status
st.markdown("---")
dependency_status = []
dependency_status.append("✅ Core: Streamlit, Pandas, NumPy")
dependency_status.append("✅ Matplotlib" if MATPLOTLIB_AVAILABLE else "❌ Matplotlib")
dependency_status.append("✅ Plotly" if PLOTLY_AVAILABLE else "❌ Plotly")

st.markdown(f"**Dependency Status:** {' | '.join(dependency_status)}")
