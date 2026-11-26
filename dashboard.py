"""Interactive SOC dashboard. Run with:  streamlit run dashboard.py"""
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from sentinel.alerts import to_frame
from sentinel.detect import detect
from sentinel.generate import generate
from sentinel.parser import load, load_csv, parse_lines
from sentinel.stats import Z_THRESHOLD, traffic_zscores

st.set_page_config(page_title="CyberSentinel", page_icon="🛡️", layout="wide")
SEV_COLORS = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#64748b"}
REAL = Path("data/SSH.log")


@st.cache_data(show_spinner="Running detectors...")
def analyze(source: str, raw: bytes | None = None, name: str = ""):
    if source == "demo":
        df = generate()
    elif source == "real":
        df = load(REAL)
    elif name.endswith(".csv"):
        import io
        df = load_csv(io.BytesIO(raw))
    else:
        df = parse_lines(raw.decode("utf-8", errors="ignore").splitlines())
    alerts, obs = detect(df, with_observations=True)
    return df, to_frame(alerts), to_frame(obs)


@st.cache_data(show_spinner="Scoring detectors on 5 labeled datasets...")
def accuracy():
    from sentinel.evaluate import evaluate
    return evaluate()


st.title("🛡️ CyberSentinel")
st.caption("Threat detection for authentication logs: rules + z-scores + per-user baselines + "
           "Isolation Forest, with risk-based correlation and MITRE ATT&CK mapping.")

with st.sidebar:
    st.header("Data source")
    options = ["Demo company (labeled attacks)"] + (["Real SSH server (Loghub)"] if REAL.exists() else [])
    choice = st.radio("Logs", options + ["Upload a file"])
    upload = st.file_uploader("CSV, auth.log, Windows CSV, or Cowrie JSON",
                              type=["csv", "log", "txt", "json"]) if choice == "Upload a file" else None
    sev_filter = st.multiselect("Severity", list(SEV_COLORS), default=["critical", "high", "medium"])

if choice.startswith("Demo"):
    df, alerts, obs = analyze("demo")
elif choice.startswith("Real"):
    df, alerts, obs = analyze("real")
elif upload is not None:
    df, alerts, obs = analyze("upload", upload.getvalue(), upload.name)
else:
    st.info("Upload a log file to begin.")
    st.stop()

if df.empty:
    st.warning("No login events found.")
    st.stop()

shown = alerts[alerts.severity.isin(sev_filter)]
c = st.columns(5)
c[0].metric("Login events", f"{len(df):,}")
c[1].metric("Source IPs", f"{df.ip.nunique():,}")
c[2].metric("Failure rate", f"{(df.event == 'login_failed').mean():.1%}")
c[3].metric("Alerts", f"{len(alerts):,}")
c[4].metric("Critical", int((alerts.severity == "critical").sum()))

tabs = st.tabs(["🚨 Alerts", "📈 Timeline", "🌍 Map", "🧠 ATT&CK", "🎯 Detector accuracy", "🔕 Observations"])

with tabs[0]:
    st.dataframe(
        shown.drop(columns=["score"]).style.map(
            lambda v: f"color: {SEV_COLORS.get(v, 'inherit')}; font-weight: 600", subset=["severity"]),
        use_container_width=True, hide_index=True, height=480)
    st.download_button("Download alerts (JSON)", shown.to_json(orient="records", date_format="iso"),
                       "alerts.json", "application/json")

with tabs[1]:
    z = traffic_zscores(df)
    fig = go.Figure()
    fig.add_bar(x=z.index, y=z.failures, name="failed logins / hour", marker_color="#94a3b8")
    sp = z[z.anomaly]
    fig.add_scatter(x=sp.index, y=sp.failures, mode="markers", name=f"z > {Z_THRESHOLD:g}",
                    marker=dict(color="#b91c1c", size=10, symbol="x"))
    if len(alerts):
        a = alerts.assign(time=pd.to_datetime(alerts.time))
        fig.add_scatter(x=a.time, y=[z.failures.max() * 1.05] * len(a), mode="markers",
                        marker=dict(color=a.severity.map(SEV_COLORS), size=7), name="alerts",
                        text=a.rule + " · " + a.ip, hoverinfo="text+x")
    fig.update_layout(height=420, margin=dict(l=0, r=0, t=10, b=0), legend=dict(orientation="h"))
    st.plotly_chart(fig, use_container_width=True)
    top = (df[df.event == "login_failed"].groupby("ip").size().nlargest(15)
           .rename("failed").reset_index())
    st.plotly_chart(px.bar(top, x="failed", y="ip", orientation="h", title="Top attacking IPs")
                    .update_layout(height=420, yaxis=dict(autorange="reversed")), use_container_width=True)

with tabs[2]:
    geo = df.dropna(subset=["lat", "lon"])
    if geo.empty:
        st.info("This log format has no location data. Load the demo dataset to see the map.")
    else:
        pts = (geo.groupby(["city", "lat", "lon", "event"]).size().rename("n").reset_index())
        fig = px.scatter_geo(pts, lat="lat", lon="lon", size="n", color="event", hover_name="city",
                             color_discrete_map={"login_success": "#2563eb", "login_failed": "#dc2626"},
                             projection="natural earth")
        travel = alerts[alerts.rule == "impossible_travel"]
        ok = geo[geo.event == "login_success"].sort_values("timestamp")
        for r in travel.itertuples():
            u = ok[ok.user == r.user]
            t = pd.Timestamp(r.time)
            prev, cur = u[u.timestamp < t].tail(1), u[u.timestamp == t].head(1)
            if len(prev) and len(cur):
                fig.add_trace(go.Scattergeo(lat=[prev.lat.iat[0], cur.lat.iat[0]],
                                            lon=[prev.lon.iat[0], cur.lon.iat[0]], mode="lines",
                                            line=dict(color="#b91c1c", width=2), showlegend=False,
                                            hoverinfo="text", text=r.detail))
        fig.update_layout(height=520, margin=dict(l=0, r=0, t=0, b=0))
        st.plotly_chart(fig, use_container_width=True)
        st.caption("Red lines = impossible travel (same account, two places, faster than a plane).")

with tabs[3]:
    if len(alerts):
        m = alerts.groupby(["tactic", "technique"]).size().rename("alerts").reset_index()
        st.plotly_chart(px.treemap(m, path=["tactic", "technique"], values="alerts")
                        .update_layout(height=480, margin=dict(l=0, r=0, t=10, b=0)),
                        use_container_width=True)
        st.dataframe(m.sort_values("alerts", ascending=False), hide_index=True, use_container_width=True)

with tabs[4]:
    st.write("Precision/recall measured on 5 synthetic companies with 105 labeled attacks "
             "(7 types). Run it yourself: `python -m sentinel evaluate`.")
    res, by_type = accuracy()
    st.dataframe(res.style.format({"precision": "{:.1%}", "recall": "{:.1%}", "f1": "{:.2f}",
                                   "alerts": "{:.0f}", "true_alerts": "{:.0f}"}),
                 use_container_width=True)
    st.dataframe(by_type.style.format({"recall": "{:.0%}"}), use_container_width=True)

with tabs[5]:
    st.write("Low-risk signals that were **not** escalated because nothing else corroborated them "
             "(risk-based alerting keeps these out of the alert queue).")
    st.dataframe(obs.drop(columns=["score"]), use_container_width=True, hide_index=True)
