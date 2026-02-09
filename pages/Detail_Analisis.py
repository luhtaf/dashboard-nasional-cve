
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from utils.elk_connector import ELKConnector

# Custom Logic for Detail Analysis
st.set_page_config(
    page_title="Advanced Threat Analysis",
    page_icon="🔬",
    layout="wide"
)

# Reuse Styles (Ideally in a shared file, but replicating for simplicity as per single-file logic constraints sometimes)
st.markdown("""
<style>
    /* Global Styles */
    body {
        font-family: 'Inter', sans-serif;
        background-color: #0e1117;
        color: #e0e0e0;
    }
    
    /* Metrics Cards */
    div[data-testid="metric-container"] {
        background-color: rgba(28, 31, 46, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 10px;
        padding: 15px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        backdrop-filter: blur(10px);
    }
    
    /* Table headers */
    thead tr th:first-child {display:none}
    tbody th {display:none}
    
    .stDataFrame {
        border-radius: 10px;
        overflow: hidden;
        border: 1px solid rgba(255,255,255,0.1);
    }

    /* Plotly */
    .js-plotly-plot .plotly .main-svg {
        background: transparent !important;
    }
</style>
""", unsafe_allow_html=True)

connector = ELKConnector()

st.title("🔬 Advanced Threat Analysis")
st.markdown("Deep dive into vulnerability logs, filter by specific attributes, and identify patterns.")

# Sidebar Filters
st.sidebar.header("Deep Filters")
time_range = st.sidebar.selectbox("Base Time Range", ["30d", "90d", "1y"], index=0)

# Fetch base data
with st.spinner("Loading Data..."):
    df = connector.get_data(time_range=time_range)

if df.empty:
    st.error("No data available.")
    st.stop()

# Dynamic Filters based on data
all_sectors = sorted(df['Sektor'].unique().tolist())
all_severs = sorted(df['Severity'].unique().tolist())
all_orgs = sorted(df['Organisasi'].unique().tolist())

col_f1, col_f2, col_f3 = st.sidebar.columns(3) # Not sidebar columns, sidebar widgets are stacked.

selected_sectors = st.sidebar.multiselect("Filter by Sector", all_sectors, default=all_sectors)
selected_severities = st.sidebar.multiselect("Filter by Severity", all_severs, default=all_severs)
selected_orgs = st.sidebar.multiselect("Filter by Organization", all_orgs, default=[])

# Apply Filters
filtered_df = df[
    (df['Sektor'].isin(selected_sectors)) & 
    (df['Severity'].isin(selected_severities))
]

if selected_orgs:
    filtered_df = filtered_df[filtered_df['Organisasi'].isin(selected_orgs)]

st.markdown(f"### Analysis View ({len(filtered_df)} records)")

# --- Charts: Heatmap & Box Plot ---
c1, c2 = st.columns(2)

with c1:
    st.subheader("Severity vs. Sector Correlation")
    # Pivot table for heatmap
    heatmap_data = filtered_df.groupby(['Sektor', 'Severity']).size().reset_index(name='Count')
    heatmap_pivot = heatmap_data.pivot(index='Sektor', columns='Severity', values='Count').fillna(0)
    
    # Sort columns by severity logic
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    heatmap_pivot = heatmap_pivot.reindex(columns=[c for c in severity_order if c in heatmap_pivot.columns], fill_value=0)
    
    fig_heat = px.imshow(heatmap_pivot, 
                         color_continuous_scale='Reds',
                         aspect='auto',
                         text_auto=True,
                         title="Heatmap: Sektor x Severity Analysis")
    fig_heat.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#e0e0e0',
    )
    st.plotly_chart(fig_heat, use_container_width=True)

with c2:
    st.subheader("Vulnerability Score Distribution")
    # Box plot of scores by Sector
    fig_box = px.box(filtered_df, x='Sektor', y='Score', 
                     title="CVSS Score Distribution by Sector",
                     color='Sektor',
                     points='outliers') # minimal points
    fig_box.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#e0e0e0',
        showlegend=False
    )
    st.plotly_chart(fig_box, use_container_width=True)

# --- Detailed Data Table ---
st.subheader("Raw Data Inspector")

# Column Configuration for Styler
st.dataframe(
    filtered_df[['@timestamp', 'Organisasi', 'Sektor', 'Severity', 'Vuln', 'Target', 'Score']],
    use_container_width=True,
    column_config={
        "@timestamp": st.column_config.DatetimeColumn("Detected At", format="D MMM YYYY, HH:mm"),
        "Score": st.column_config.ProgressColumn("CVSS Score", min_value=0, max_value=10, format="%.1f"),
        "Severity": st.column_config.TextColumn("Severity"),
    },
    hide_index=True
)

# Download Button
csv = filtered_df.to_csv(index=False).encode('utf-8')
st.download_button(
    "Download Filtered Data (CSV)",
    csv,
    "filtered_threat_data.csv",
    "text/csv",
    key='download-csv'
)

# Navigation
st.markdown("---")
if st.button("← Back to Overview"):
    st.switch_page("Home.py")

