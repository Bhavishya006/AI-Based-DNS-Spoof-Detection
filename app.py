from __future__ import annotations
import sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import pandas as pd
import plotly.express as px
import streamlit as st
from dns_detector.simulator import generate_records, SCENARIOS
from dns_detector.engine import analyze
from dns_detector.parser import read_pcap
from dns_detector.store import save_events, load_events
from dns_detector.model import train_model

st.set_page_config(page_title="DNS Anomaly Lab", page_icon="🛡️", layout="wide")
st.markdown("""<style>.stApp{background:#0b1220;color:#e5edf7}.block-container{padding-top:1.3rem}.metric-card{background:#121e31;border:1px solid #243650;border-radius:14px;padding:16px}.small{color:#9fb0c5}</style>""", unsafe_allow_html=True)
st.title("🛡️ DNS Spoofing Anomaly Detection")
st.caption("Local defensive prototype · simulated data is labeled · anomalies are signals, not proof of attack")
page = st.sidebar.radio("Workspace", ["Overview", "Simulation Lab", "PCAP Analyzer", "Live Monitor", "Alerts Center"])
st.sidebar.info("DNS over HTTPS/TLS payloads are encrypted and cannot be inspected by ordinary packet parsing.")

def present(events):
    if not events: return pd.DataFrame()
    df = pd.DataFrame(events)
    return df

if page == "Simulation Lab":
    st.header("Simulation Lab")
    a,b,c,d = st.columns(4)
    mode=a.selectbox("Traffic mix", ["Mixed","Normal only","Suspicious only"])
    scenario=b.selectbox("Scenario", ["Random"]+SCENARIOS)
    count=c.number_input("Records", 1, 1000, 100)
    seed=d.number_input("Seed (reproducible)", 0, 2**31-1, 42)
    if st.button("Generate and analyze", type="primary"):
        records=generate_records(count,mode,seed,scenario)
        result=analyze(records); save_events(result); st.session_state["last_results"]=result
    results=st.session_state.get("last_results",[])
    if results:
        df=present(results)
        st.dataframe(df[["timestamp","domain","ground_truth","status","severity","anomaly_score","detection_type","detection_reason"]], use_container_width=True, hide_index=True)
        st.download_button("Download results CSV", df.to_csv(index=False), "dns_simulation_results.csv", "text/csv")
        actual=df.ground_truth.ne("normal"); predicted=df.status.ne("NORMAL")
        st.caption(f"Demo comparison · {int((actual==predicted).sum())}/{len(df)} broad normal-vs-suspicious labels aligned. This is not a validated benchmark.")
elif page == "PCAP Analyzer":
    st.header("PCAP Analyzer")
    st.caption("Files are parsed locally and not uploaded to an external service. Maximum size: 20 MB.")
    file=st.file_uploader("Choose .pcap or .pcapng", type=["pcap","pcapng"])
    expected=st.text_input("Expected DNS resolver IP (optional)", "")
    if file and len(file.getvalue()) <= 20*1024*1024 and st.button("Analyze capture", type="primary"):
        try:
            with tempfile.NamedTemporaryFile(suffix=Path(file.name).suffix) as temp:
                temp.write(file.getvalue()); temp.flush(); summary=read_pcap(temp.name,expected or None)
            results=analyze(summary["records"]); save_events(results); st.session_state["pcap_results"]=results; st.session_state["pcap_summary"]=summary
        except Exception as e: st.error(f"Could not parse capture: {e}")
    elif file and len(file.getvalue()) > 20*1024*1024: st.error("File exceeds the 20 MB limit.")
    if st.session_state.get("pcap_summary"):
        s=st.session_state["pcap_summary"]
        st.write({k:v for k,v in s.items() if k!="records"})
        df=present(st.session_state["pcap_results"]); st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button("Export parsed records and detections", df.to_csv(index=False), "pcap_dns_analysis.csv", "text/csv")
elif page == "Live Monitor":
    st.header("Live DNS Monitor (optional)")
    st.warning("Live capture requires Npcap and suitable Windows permissions. Select an interface explicitly. Captures DNS UDP/TCP only; no packets are sent.")
    try:
        from scapy.all import get_if_list, sniff
        interfaces=get_if_list()
    except Exception as e:
        interfaces=[]; st.error(f"Scapy capture is unavailable: {e}. Use Simulation Lab or PCAP Analyzer instead.")
    selected=st.selectbox("Network interface", interfaces) if interfaces else None
    duration=st.slider("Capture duration (seconds)", 5, 60, 10)
    if st.button("Start selected-interface capture", disabled=not selected):
        try:
            from scapy.all import sniff
            packets=sniff(iface=selected, filter="udp port 53 or tcp port 53", timeout=duration, store=True)
            from dns_detector.parser import parse_packet
            rec=[x for p in packets if (x:=parse_packet(p,"LIVE"))]
            events=analyze(rec); save_events(events); st.session_state["live_results"]=events
        except Exception as e: st.error(f"Capture failed. Check Npcap, interface selection, and permissions: {e}")
    lr=st.session_state.get("live_results",[])
    st.metric("Recent captured DNS events",len(lr)); st.dataframe(present(lr), use_container_width=True, hide_index=True)
    st.caption("The bounded capture stops after the selected duration. Do not capture traffic without authorization.")
elif page == "Alerts Center":
    st.header("Alerts Center")
    events=[e for e in load_events() if e.get("status")!="NORMAL"]
    df=present(events)
    if not df.empty:
        sev=st.multiselect("Severity",["INFO","LOW","MEDIUM","HIGH"], default=["LOW","MEDIUM","HIGH"])
        df=df[df.severity.isin(sev)]
        st.dataframe(df[[c for c in ["timestamp","domain","source_ip","source_type","detection_type","severity","detection_reason","anomaly_score","status"] if c in df]], use_container_width=True, hide_index=True)
        st.download_button("Export alerts CSV",df.to_csv(index=False),"dns_alerts.csv","text/csv")
    else: st.info("No alerts recorded yet. Run the Simulation Lab or analyze a PCAP.")
else:
    st.header("Overview")
    events=load_events(); df=present(events)
    if df.empty: st.info("No events yet. Start with the Simulation Lab; sample data is generated locally.")
    else:
        total=len(df); suspicious=int((df.status!="NORMAL").sum()); spoof=int((df.status=="POTENTIAL_DNS_SPOOFING").sum()); anomalous=int(df.ml_anomaly.sum())
        cols=st.columns(5)
        for col,label,val in zip(cols,["DNS records","Normal","Suspicious","Potential spoofing","ML anomalies"],[total,total-suspicious,suspicious,spoof,anomalous]): col.metric(label,val)
        left,right=st.columns(2)
        with left: st.plotly_chart(px.pie(df,names="status",title="Final classifications",hole=.45,template="plotly_dark"),use_container_width=True)
        with right: st.plotly_chart(px.histogram(df,x="severity",color="severity",title="Alert severity",template="plotly_dark"),use_container_width=True)
        trend=df.copy(); trend["timestamp"]=pd.to_datetime(trend.timestamp,errors="coerce",utc=True); trend=trend.dropna(subset=["timestamp"]).set_index("timestamp").resample("1min").size().rename("events").reset_index()
        st.plotly_chart(px.line(trend,x="timestamp",y="events",title="DNS event frequency (per minute)",template="plotly_dark"),use_container_width=True)
        st.plotly_chart(px.bar(df.assign(rule_hit=df.detection_type.ne("None")),x="source_type",y="ml_anomaly",color="rule_hit",title="Rule and ML detections by source",template="plotly_dark"),use_container_width=True)
    with st.expander("Model workflow"):
        st.write("Isolation Forest is fitted only on an independent generated normal-only training corpus. Its decision score is an unusualness measure, not attack probability.")
        contamination=st.slider("Contamination",0.01,0.20,0.05,0.01)
        if st.button("Retrain from generated normal training data"):
            train_model(contamination=contamination); st.success("Model saved locally. Existing evaluation records were not used.")
