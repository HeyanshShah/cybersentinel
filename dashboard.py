"""Interactive dashboard. Run with:  streamlit run dashboard.py"""
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from sentinel.alerts import to_frame
from sentinel.detect import detect
from sentinel.generate import generate
from sentinel.parser import load_csv, parse_auth_log
from sentinel.stats import Z_THRESHOLD, traffic_zscores

st.set_page_config(page_title="CyberSentinel", page_icon="🛡️", layout="wide")
st.title("🛡️ CyberSentinel")
st.caption("Anomaly-based threat detection for login logs: rules + z-score statistics.")

with st.sidebar:
    st.header("Data source")
    upload = st.file_uploader("Upload CSV or Linux auth.log", type=["csv", "log", "txt"])
    st.caption("No file? A week of generated demo logs with hidden attacks is used.")

if upload is None:
    df = generate()
elif upload.name.endswith(".csv"):
    df = load_csv(upload)
else:
    df = parse_auth_log(upload.getvalue().decode("utf-8", errors="ignore").splitlines())

if df.empty:
    st.warning("No login events found in that file.")
    st.stop()

alerts = to_frame(detect(df))
z = traffic_zscores(df)

c = st.columns(4)
c[0].metric("Events", f"{len(df):,}")
c[1].metric("Unique IPs", df.ip.nunique())
c[2].metric("Failed logins", int((df.event == "login_failed").sum()))
c[3].metric("Alerts", len(alerts),
            delta=f"{int((alerts.severity == 'critical').sum())} critical", delta_color="inverse")

st.subheader("Alerts")
colors = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#64748b"}
st.dataframe(
    alerts.drop(columns="score").style.map(
        lambda v: f"color: {colors.get(v, 'inherit')}; font-weight: 600", subset=["severity"]),
    use_container_width=True, hide_index=True)

left, right = st.columns([3, 2])
with left:
    st.subheader("Failed logins per hour")
    fig = go.Figure()
    fig.add_bar(x=z.index, y=z.failures, name="failed logins", marker_color="#94a3b8")
    spikes = z[z.anomaly]
    fig.add_scatter(x=spikes.index, y=spikes.failures, mode="markers", name="anomaly (z>3)",
                    marker=dict(color="#b91c1c", size=12, symbol="x"))
    fig.update_layout(height=340, margin=dict(l=0, r=0, t=10, b=0), legend=dict(orientation="h"))
    st.plotly_chart(fig, use_container_width=True)
with right:
    st.subheader("Anomaly score (z) per hour")
    fig2 = px.line(z.reset_index(), x="timestamp", y="z_failures")
    fig2.add_hline(y=Z_THRESHOLD, line_dash="dash", line_color="#b91c1c",
                   annotation_text=f"threshold z={Z_THRESHOLD:g}")
    fig2.update_layout(height=340, margin=dict(l=0, r=0, t=10, b=0), yaxis_title="z-score")
    st.plotly_chart(fig2, use_container_width=True)

st.subheader("Top IPs by failed logins")
top = (df[df.event == "login_failed"].groupby(["ip", "country"]).size()
       .rename("failed").reset_index().sort_values("failed", ascending=False).head(10))
fig3 = px.bar(top, x="failed", y="ip", color="country", orientation="h")
fig3.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0), yaxis=dict(autorange="reversed"))
st.plotly_chart(fig3, use_container_width=True)

with st.expander("Raw events"):
    st.dataframe(df, use_container_width=True, hide_index=True)
