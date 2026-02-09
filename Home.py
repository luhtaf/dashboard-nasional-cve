
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from utils.elk_connector import ELKConnector

# Page Config
st.set_page_config(
    page_title="Nasional CVE Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS
st.markdown("""
<style>
    body {
        font-family: 'Inter', sans-serif;
        background-color: #0e1117;
    }
    .metric-card {
        background-color: #1e2130;
        border: 1px solid #2b3042;
        padding: 15px;
        border-radius: 8px;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .metric-label {
        color: #a0a0a0;
        font-size: 0.9em;
        margin-bottom: 5px;
    }
    .metric-value {
        color: #ffffff;
        font-size: 1.8em;
        font-weight: bold;
    }
    .stPlotlyChart {
        background-color: #1e2130;
        border-radius: 8px;
        padding: 10px;
    }
    /* Hide default header to make it look like a standalone app */
    header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# Initialize Connector
connector = ELKConnector()

# Sidebar
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Dashboard Nasional", "Detail Analisis"])

if page == "Detail Analisis":
    st.switch_page("pages/Detail_Analisis.py")

# Main Dashboard Logic
st.title("🛡️ Dashboard Monitoring Kerentanan Siber Nasional")
st.markdown("Overview kerentanan CVE pada sektor-sektor kritis nasional (Berasarkan Data Kibana)")

# Filters
col_filter, _ = st.columns([1, 3])
with col_filter:
    time_range = st.selectbox("Rentang Waktu", ["30d", "90d", "1y", "All"], index=1)

# Fetch Data
with st.spinner("Mengambil data dari ELK..."):
    df = connector.get_data(time_range=time_range)

if df.empty:
    st.error("Gagal mengambil data atau data kosong.")
    st.stop()

# --- Section 1: Sector Organization Metrics (Scrollable concept realized via columns) ---
st.subheader("Jumlah Organisasi Terdampak per Sektor")

sectors_target = [
    "Administrasi Pemerintahan", "Keuangan", "Transportasi", 
    "Pangan", "ESDM", "TIK", "Kesehatan", "Pertahanan", "Lainnya"
]

cols = st.columns(len(sectors_target))
for idx, sector in enumerate(sectors_target):
    # Filter count unique organizations in this sector
    count = df[df['Sektor'] == sector]['Organisasi'].nunique()
    with cols[idx]:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">{sector}</div>
            <div class="metric-value">{count}</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("---")

# --- Section 2: Global KPIs ---
kpi_c1, kpi_c2, kpi_c3, kpi_c4 = st.columns(4)

total_vuln_hits = len(df)
unique_vulns = df['Vuln'].nunique()
unique_orgs = df['Organisasi'].nunique()
unique_assets = df['Source'].nunique()

with kpi_c1:
    st.metric("Total Hit Kerentanan", f"{total_vuln_hits:,}")
with kpi_c2:
    st.metric("Kerentanan Unik", f"{unique_vulns:,}")
with kpi_c3:
    st.metric("Organisasi Terdampak", f"{unique_orgs:,}")
with kpi_c4:
    st.metric("Aset Unik", f"{unique_assets:,}")

# --- Section 3: Severity Breakdown KPIs ---
st.markdown("### Distribusi Keparahan (Severity)")
sev_c1, sev_c2, sev_c3, sev_c4 = st.columns(4)

def get_sev_count(sev):
    return len(df[df['Severity'] == sev])

with sev_c1:
    st.markdown(f'<div class="metric-card" style="border-top: 3px solid #ff4d4f;"><div class="metric-label">CRITICAL</div><div class="metric-value">{get_sev_count("CRITICAL"):,}</div></div>', unsafe_allow_html=True)
with sev_c2:
    st.markdown(f'<div class="metric-card" style="border-top: 3px solid #ff7a45;"><div class="metric-label">HIGH</div><div class="metric-value">{get_sev_count("HIGH"):,}</div></div>', unsafe_allow_html=True)
with sev_c3:
    st.markdown(f'<div class="metric-card" style="border-top: 3px solid #ffa940;"><div class="metric-label">MEDIUM</div><div class="metric-value">{get_sev_count("MEDIUM"):,}</div></div>', unsafe_allow_html=True)
with sev_c4:
    st.markdown(f'<div class="metric-card" style="border-top: 3px solid #73d13d;"><div class="metric-label">LOW</div><div class="metric-value">{get_sev_count("LOW"):,}</div></div>', unsafe_allow_html=True)

st.markdown("---")

# --- Section 4: Main Visualizations ---
row1_c1, row1_c2 = st.columns(2)

# Chart 1: Persentase Vuln (Donut)
with row1_c1:
    st.subheader("Persentase Keparahan Kerentanan")
    sev_counts = df['Severity'].value_counts().reset_index()
    sev_counts.columns = ['Severity', 'Count']
    color_map = {'CRITICAL': '#ff4d4f', 'HIGH': '#ff7a45', 'MEDIUM': '#ffa940', 'LOW': '#73d13d', 'UNKNOWN': '#bfbfbf'}
    
    fig_pie = px.pie(sev_counts, values='Count', names='Severity', 
                     color='Severity', color_discrete_map=color_map, hole=0.5)
    fig_pie.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font_color='white')
    st.plotly_chart(fig_pie, use_container_width=True)

# Chart 2: Top 10 Org Terdampak (Bar) - "Persentase Organisasi Terdampak" style
with row1_c2:
    st.subheader("Top 10 Organisasi Terdampak (Total Hits)")
    top_orgs = df['Organisasi'].value_counts().head(10).reset_index()
    top_orgs.columns = ['Organisasi', 'Hits']
    
    fig_bar_org = px.bar(top_orgs, x='Hits', y='Organisasi', orientation='h', 
                         color='Hits', color_continuous_scale='Blues')
    fig_bar_org.update_layout(yaxis={'categoryorder':'total ascending'}, plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font_color='white')
    st.plotly_chart(fig_bar_org, use_container_width=True)

# --- Section 5: Top 5 Assets & Vulns ---
row2_c1, row2_c2 = st.columns(2)

with row2_c1:
    st.subheader("Top 5 Aset Terdampak")
    top_assets = df['Source'].value_counts().head(5).reset_index()
    top_assets.columns = ['Aset', 'Hits']
    fig_asset = px.bar(top_assets, x='Aset', y='Hits', color='Hits', color_continuous_scale='Viridis')
    fig_asset.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font_color='white')
    st.plotly_chart(fig_asset, use_container_width=True)

with row2_c2:
    st.subheader("Top 5 Jenis Kerentanan")
    top_vulns = df['Vuln'].value_counts().head(5).reset_index()
    top_vulns.columns = ['Vulnerability', 'Hits']
    fig_vuln = px.bar(top_vulns, x='Vulnerability', y='Hits', color='Hits', color_continuous_scale='Magma')
    fig_vuln.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font_color='white')
    st.plotly_chart(fig_vuln, use_container_width=True)

# --- Section 6: CISA KEV Special Section ---
if 'hasCisa' in df.columns and df['hasCisa'].any():
    st.markdown("---")
    st.subheader("⚠️ CISA Known Exploited Vulnerabilities (KEV)")
    
    cisa_df = df[df['hasCisa'] == True]
    
    cisa_c1, cisa_c2, cisa_c3 = st.columns(3)
    with cisa_c1:
        st.metric("Total Hit CISA KEV", f"{len(cisa_df):,}")
    with cisa_c2:
        st.metric("Kerentanan CISA Unik", f"{cisa_df['Vuln'].nunique():,}")
    with cisa_c3:
        st.metric("Organisasi Terdampak CISA", f"{cisa_df['Organisasi'].nunique():,}")
    
    st.dataframe(
        cisa_df[['@timestamp', 'Vuln', 'Organisasi', 'Severity', 'Score']].head(50),
        use_container_width=True,
        hide_index=True
    )

# --- Section 7: Timeline ---
st.markdown("---")
st.subheader("Timeline Deteksi Kerentanan")

timeline_df = df.set_index('@timestamp').resample('D').size().reset_index(name='Count')
fig_line = px.area(timeline_df, x='@timestamp', y='Count', line_shape='spline')
fig_line.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font_color='white', xaxis_title=None)
st.plotly_chart(fig_line, use_container_width=True)

st.markdown("---")
st.caption("Dashboard generated based on Kibana Export Structure. © 2026")
