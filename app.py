import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

# Set page configuration
st.set_page_config(
    page_title="Data Analysis Dashboard",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .error-box {
        background-color: #ffebee;
        border: 1px solid #f44336;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
    }
    .success-box {
        background-color: #e8f5e8;
        border: 1px solid #4caf50;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Title and description
st.markdown('<h1 class="main-header">📊 Data Analysis Dashboard</h1>', unsafe_allow_html=True)
st.markdown("""
**Professional Data Analysis Tool with Robust Error Handling**

This application provides comprehensive data analysis capabilities with built-in error handling 
for common issues like missing columns (KeyError). Upload your data or generate sample data to begin analysis.
""")

# Sidebar configuration
st.sidebar.header("🛠️ Configuration")

# Data source selection
data_source = st.sidebar.selectbox(
    "Select Data Source",
    ["Upload CSV File", "Generate Sample Data", "Create Custom Dataset"]
)

def safe_column_access(df, column_name, operation="mean", default_value=None):
    """
    Safely access DataFrame columns with comprehensive error handling
    
    Args:
        df: pandas DataFrame
        column_name: name of the column to access
        operation: operation to perform ('mean', 'sum', 'count', etc.)
        default_value: value to return if column doesn't exist
    
    Returns:
        Result of operation or default_value if column doesn't exist
    """
    try:
        if column_name in df.columns:
            column_data = df[column_name]
            
            if operation == "mean":
                # Handle zeros by replacing with NaN, then calculate mean
                result = column_data.replace(0, np.nan).mean()
                return result if not pd.isna(result) else default_value
            elif operation == "sum":
                return column_data.sum()
            elif operation == "count":
                return len(column_data)
            elif operation == "std":
                return column_data.std()
            else:
                return column_data
        else:
            return default_value
    except Exception as e:
        st.error(f"Error accessing column '{column_name}': {str(e)}")
        return default_value

def standardize_column_names(df):
    """Standardize column names to avoid common naming issues"""
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('-', '_')
    return df

def suggest_similar_columns(df, target_column):
    """Suggest similar column names based on keywords"""
    keywords = target_column.lower().split('_')
    similar_columns = []
    
    for col in df.columns:
        col_lower = col.lower()
        if any(keyword in col_lower for keyword in keywords):
            similar_columns.append(col)
    
    return similar_columns

def generate_sample_data(num_rows=1000):
    """Generate sample data with inter_arrival_time column"""
    np.random.seed(42)  # For reproducible results
    
    data = {
        'timestamp': pd.date_range(start='2024-01-01', periods=num_rows, freq='1min'),
        'inter_arrival_time': np.random.exponential(2.0, num_rows),  # Exponential distribution
        'request_count': np.random.poisson(5, num_rows),
        'response_time': np.random.gamma(2, 2, num_rows),
        'server_load': np.random.beta(2, 5, num_rows) * 100,
        'error_rate': np.random.uniform(0, 0.1, num_rows),
        'user_id': np.random.randint(1000, 9999, num_rows),
        'session_duration': np.random.normal(300, 100, num_rows)
    }
    
    # Add some zeros to inter_arrival_time to demonstrate the replace(0, np.nan) functionality
    zero_indices = np.random.choice(num_rows, size=int(num_rows * 0.1), replace=False)
    for idx in zero_indices:
        data['inter_arrival_time'][idx] = 0
    
    return pd.DataFrame(data)

# Data loading logic
df = None

if data_source == "Upload CSV File":
    uploaded_file = st.sidebar.file_uploader(
        "Choose a CSV file",
        type="csv",
        help="Upload a CSV file containing your data"
    )
    
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            df = standardize_column_names(df)
            st.success(f"✅ Successfully loaded {len(df)} rows from {uploaded_file.name}")
        except Exception as e:
            st.error(f"❌ Error loading file: {str(e)}")
            st.stop()

elif data_source == "Generate Sample Data":
    num_rows = st.sidebar.slider("Number of rows", 100, 5000, 1000)
    if st.sidebar.button("🎲 Generate Data"):
        df = generate_sample_data(num_rows)
        st.success(f"✅ Generated {len(df)} rows of sample data")

elif data_source == "Create Custom Dataset":
    st.sidebar.info("Custom dataset creation coming soon!")

# Main analysis section
if df is not None:
    # **Data Overview Section**
    st.header("📋 Data Overview")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Available Columns")
        st.write("**Column Names:**", df.columns.tolist())
        st.write("**Data Shape:**", df.shape)
        
        # Display first few rows
        st.subheader("Sample Data")
        st.dataframe(df.head(10), use_container_width=True)
    
    with col2:
        st.subheader("Data Types")
        st.write(df.dtypes.to_frame('Data Type'))
        
        # Basic statistics
        st.subheader("Basic Info")
        st.write(f"**Total Rows:** {len(df)}")
        st.write(f"**Total Columns:** {len(df.columns)}")
        st.write(f"**Memory Usage:** {df.memory_usage(deep=True).sum() / 1024:.2f} KB")

    # **Inter-Arrival Time Analysis Section**
    st.header("⏱️ Inter-Arrival Time Analysis")
    
    # This is where we solve the original KeyError problem
    target_column = "inter_arrival_time"
    
    # Check if the target column exists
    if target_column in df.columns:
        st.markdown(f'<div class="success-box">✅ <strong>Column Found:</strong> "{target_column}" is present in your data!</div>', unsafe_allow_html=True)
        
        # Perform the calculation safely
        mean_arrival = safe_column_access(df, target_column, "mean", 0)
        std_arrival = safe_column_access(df, target_column, "std", 0)
        count_nonzero = len(df[df[target_column] > 0])
        
        # Display metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Mean Inter-arrival Time", f"{mean_arrival:.3f}s" if mean_arrival else "N/A")
        with col2:
            st.metric("Standard Deviation", f"{std_arrival:.3f}s" if std_arrival else "N/A")
        with col3:
            st.metric("Non-zero Values", count_nonzero)
        with col4:
            st.metric("Zero Values Replaced", len(df) - count_nonzero)
        
        # Visualization
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Distribution of Inter-arrival Times")
            # Filter out zeros for better visualization
            filtered_data = df[df[target_column] > 0][target_column]
            
            if len(filtered_data) > 0:
                fig, ax = plt.subplots(figsize=(10, 6))
                ax.hist(filtered_data, bins=30, alpha=0.7, edgecolor='black')
                ax.set_xlabel('Inter-arrival Time (seconds)')
                ax.set_ylabel('Frequency')
                ax.set_title('Distribution of Inter-arrival Times (excluding zeros)')
                st.pyplot(fig)
            else:
                st.warning("No non-zero values found for visualization")
        
        with col2:
            st.subheader("Time Series Plot")
            if 'timestamp' in df.columns:
                fig = px.line(df.head(200), x='timestamp', y=target_column, 
                             title='Inter-arrival Time Over Time (First 200 points)')
                st.plotly_chart(fig, use_container_width=True)
            else:
                fig = px.line(y=df[target_column].head(200), 
                             title='Inter-arrival Time Sequence (First 200 points)')
                st.plotly_chart(fig, use_container_width=True)
    
    else:
        st.markdown(f'<div class="error-box">❌ <strong>Column Not Found:</strong> "{target_column}" is missing from your data!</div>', unsafe_allow_html=True)
        
        # Provide debugging information
        st.subheader("🔍 Debugging Information")
        st.write("**Available columns in your dataset:**")
        for i, col in enumerate(df.columns, 1):
            st.write(f"{i}. `{col}`")
        
        # Suggest similar columns
        similar_cols = suggest_similar_columns(df, target_column)
        if similar_cols:
            st.subheader("💡 Suggested Similar Columns")
            st.info("Based on keywords, you might be looking for one of these columns:")
            for col in similar_cols:
                st.write(f"- `{col}`")
                
                # Offer to use this column instead
                if st.button(f"Use '{col}' instead", key=f"use_{col}"):
                    st.rerun()
        else:
            st.warning("No similar columns found based on common keywords.")
        
        # Provide solutions
        st.subheader("🛠️ How to Fix This Issue")
        st.markdown("""
        **Common solutions:**
        1. **Check your data source** - Ensure the CSV file or database contains the expected column
        2. **Verify column names** - Check for typos, spaces, or different capitalization
        3. **Data preprocessing** - The column might have been dropped or renamed earlier in your pipeline
        4. **Create the column** - If the data represents something else, you might need to calculate inter-arrival times
        """)

    # **Additional Analysis Sections**
    st.header("📊 Additional Analysis")
    
    analysis_tabs = st.tabs(["📈 Statistical Summary", "🔗 Correlations", "📉 Visualizations", "💾 Export Data"])
    
    with analysis_tabs[0]:
        st.subheader("Statistical Summary")
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        if len(numeric_columns) > 0:
            st.dataframe(df[numeric_columns].describe(), use_container_width=True)
        else:
            st.info("No numeric columns found for statistical analysis")
    
    with analysis_tabs[1]:
        st.subheader("Correlation Analysis")
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        if len(numeric_columns) > 1:
            correlation_matrix = df[numeric_columns].corr()
            
            fig, ax = plt.subplots(figsize=(10, 8))
            sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0, ax=ax)
            ax.set_title('Correlation Matrix')
            st.pyplot(fig)
        else:
            st.info("Need at least 2 numeric columns for correlation analysis")
    
    with analysis_tabs[2]:
        st.subheader("Data Visualizations")
        
        # Column selection for visualization
        viz_columns = st.multiselect(
            "Select columns to visualize",
            df.select_dtypes(include=[np.number]).columns.tolist(),
            default=df.select_dtypes(include=[np.number]).columns.tolist()[:2]
        )
        
        if len(viz_columns) >= 1:
            if len(viz_columns) == 1:
                fig = px.histogram(df, x=viz_columns[0], title=f'Distribution of {viz_columns[0]}')
            else:
                fig = px.scatter(df, x=viz_columns[0], y=viz_columns[1], 
                               title=f'{viz_columns[0]} vs {viz_columns[1]}')
            st.plotly_chart(fig, use_container_width=True)
    
    with analysis_tabs[3]:
        st.subheader("Export Your Data")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📥 Download as CSV"):
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download CSV file",
                    data=csv,
                    file_name=f"analyzed_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📥 Download Summary Report"):
                # Create a summary report
                summary_data = {
                    'Column': df.columns,
                    'Data_Type': df.dtypes.values,
                    'Non_Null_Count': df.count().values,
                    'Null_Count': df.isnull().sum().values
                }
                summary_df = pd.DataFrame(summary_data)
                
                summary_csv = summary_df.to_csv(index=False)
                st.download_button(
                    label="Download Summary CSV",
                    data=summary_csv,
                    file_name=f"data_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )

else:
    # Instructions when no data is loaded
    st.info("👆 Please select a data source in the sidebar to begin analysis.")
    
    st.markdown("""
    ## 🚀 Getting Started
    
    **This application helps you avoid and debug common pandas KeyError issues while providing comprehensive data analysis capabilities.**
    
    ### Features:
    - **🛡️ Robust Error Handling**: Prevents crashes from missing columns
    - **🔍 Smart Debugging**: Suggests similar column names when targets are missing
    - **📊 Comprehensive Analysis**: Statistical summaries, correlations, and visualizations
    - **📁 Flexible Data Input**: Upload CSV files or generate sample data
    - **💾 Export Capabilities**: Download results and summary reports
    
    ### How It Solves Your KeyError:
    1. **Column Validation**: Checks if columns exist before accessing them
    2. **Safe Operations**: Uses try-catch blocks for all data operations
    3. **User Feedback**: Provides clear error messages and suggestions
    4. **Fallback Options**: Offers alternatives when expected columns are missing
    
    ### Quick Start:
    1. Choose "Generate Sample Data" to see the app in action
    2. Or upload your own CSV file to analyze your data
    3. The app will safely handle missing columns and guide you through solutions
    """)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666; font-size: 0.8em;'>
    Data Analysis Dashboard | Built with Streamlit | Robust Error Handling Included
</div>
""", unsafe_allow_html=True)
