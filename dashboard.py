"""
dashboard.py — Real-Time Network Threat Analytics Dashboard.

Provides interactive visualization and monitoring for:
- Streaming ingestion overview and alert rate
- Threat alerts table with filtering, sorting, and pagination
- Offline ground-truth detection evaluation and confusion matrix
"""

import os
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard_utils import (
    get_secret_setting,
    get_mongo_connection,
    test_mongo_connection,
    get_available_runs,
    get_overview_metrics,
    get_filtered_alerts,
    get_historical_batches,
    calculate_aggregate_confusion_matrix,
    get_historical_rollups,
    get_lake_stats,
    get_backup_status,
    get_kafka_consumer_lag,
    get_cluster_status,
    human_bytes,
)

# -----------------------------------------------------------------------------
# 1. Page Configuration & Theme
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Real-Time Network Threat Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom SOC / SIEM Styling
st.markdown(
    """
    <style>
    .metric-card {
        background-color: #1e222d;
        border-radius: 8px;
        padding: 16px 20px;
        border-left: 4px solid #3b82f6;
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        margin-bottom: 12px;
    }
    .metric-title {
        font-size: 0.85rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 4px;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #f8fafc;
    }
    .metric-sub {
        font-size: 0.78rem;
        color: #64748b;
        margin-top: 4px;
    }
    .alert-badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        background-color: rgba(239, 68, 68, 0.2);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.4);
    }
    .normal-badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        background-color: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.4);
    }
    .eval-banner {
        background-color: rgba(245, 158, 11, 0.1);
        border-left: 4px solid #f59e0b;
        padding: 10px 14px;
        border-radius: 4px;
        font-size: 0.85rem;
        color: #fbbf24;
        margin-bottom: 16px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# 2. Connection Cache & Helpers
# -----------------------------------------------------------------------------
@st.cache_resource(ttl=300)
def get_cached_mongo_client(uri: str):
    """Initializes and caches a MongoClient across Streamlit reruns."""
    return get_mongo_connection(uri)


# -----------------------------------------------------------------------------
# 3. Sidebar Controls & Configuration
# -----------------------------------------------------------------------------
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("Threat Analytics")
st.sidebar.caption("Real-Time Network Streaming & Heuristic Threat Intelligence")
st.sidebar.divider()

# Connection Parameters
default_uri = get_secret_setting("MONGODB_URI", "mongodb://localhost:27017")
default_db = get_secret_setting("MONGODB_DATABASE", "network_threat_analytics")

is_cloud_or_auth = "@" in default_uri
mongo_uri = st.sidebar.text_input(
    "MongoDB URI",
    value=default_uri,
    type="password" if is_cloud_or_auth else "default",
    help="Target MongoDB connection string (Read-Only). Passwords are masked automatically.",
)
mongo_db_name = st.sidebar.text_input(
    "Database Name",
    value=default_db,
    help="Target MongoDB database name",
)

# Test Connectivity
client = get_cached_mongo_client(mongo_uri)
is_connected, conn_err = test_mongo_connection(client)

if not is_connected:
    safe_display_uri = mongo_uri.split("@")[-1] if "@" in mongo_uri else mongo_uri
    st.sidebar.error("Disconnected from MongoDB")
    st.error(
        f"❌ **Database Connection Error:** Unable to reach MongoDB host `{safe_display_uri}`.\n\n"
        f"**Error Details:** `{conn_err}`\n\n"
        "### Troubleshooting & Quick Setup:\n"
        "- **Streamlit Community Cloud:** Add `MONGODB_URI` and `MONGODB_DATABASE` to your app's **Settings > Secrets**:\n"
        "  ```toml\n"
        "  MONGODB_URI = \"mongodb+srv://<username>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority\"\n"
        "  MONGODB_DATABASE = \"network_threat_analytics\"\n"
        "  ```\n"
        "- **MongoDB Atlas IP Allowlist:** Ensure your Atlas cluster permits cloud incoming traffic (`0.0.0.0/0` in Network Access).\n"
        "- **Local Development:** Verify that the `mongod` service is running locally (`sudo systemctl status mongod`)."
    )
    if st.button("🔄 Retry Connection"):
        st.cache_resource.clear()
        st.rerun()
    st.stop()
else:
    st.sidebar.success("MongoDB Connected")

db = client[mongo_db_name]

# Active Run Selector
available_runs = get_available_runs(db)

# Exclude unwanted runs from the dashboard dropdown
excluded_runs = {"run-8a238f84", "Legacy / Unassigned"}

available_runs = [
    run for run in available_runs
    if run not in excluded_runs
]

run_options = ["All Runs"] + available_runs

# Reset stale selection if it is no longer an available option
if st.session_state.get("Streaming Run ID") not in run_options:
    st.session_state["Streaming Run ID"] = "All Runs"

selected_run = st.sidebar.selectbox(
    "Streaming Run ID",
    options=run_options,
    index=0,
    key="Streaming Run ID",
    help="Filter analytics by specific Spark consumer run UUID",
)

start_time_filter: Optional[datetime] = None
end_time_filter: Optional[datetime] = None

# Refresh Controls
st.sidebar.divider()
st.sidebar.subheader("Refresh Settings")
auto_refresh = st.sidebar.checkbox("Auto Refresh", value=False)
refresh_interval = st.sidebar.slider(
    "Refresh Interval (seconds)",
    min_value=5,
    max_value=60,
    value=10,
    step=5,
    disabled=not auto_refresh,
)

if st.sidebar.button("🔄 Refresh Data Now"):
    st.rerun()

st.sidebar.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


# -----------------------------------------------------------------------------
# 4. Main Dashboard Layout (Fragment for Controlled Refresh)
# -----------------------------------------------------------------------------
@st.fragment(run_every=refresh_interval if auto_refresh else None)
def render_dashboard_content():
    # Fetch overview data
    overview = get_overview_metrics(db, run_id=selected_run, start_time=start_time_filter, end_time=end_time_filter)
    batches = get_historical_batches(db, run_id=selected_run, start_time=start_time_filter, end_time=end_time_filter)

    # Header Title Banner
    col_hdr_left, col_hdr_right = st.columns([3, 1])
    with col_hdr_left:
        st.title("Real-Time Network Threat Analytics")
        st.caption("Structured Streaming Ingestion • Metadata-Only Heuristics • Ground-Truth Evaluation Layer")
    with col_hdr_right:
        status_color = "green" if is_connected else "red"
        st.markdown(
            f"""
            <div style="text-align: right; padding-top: 10px;">
                <span style="font-size: 0.85rem; color: #94a3b8;">Active Database:</span><br/>
                <code style="font-weight: 700;">{mongo_db_name}</code><br/>
                <span style="color: {status_color}; font-size: 0.8rem;">● Live Pipeline Active</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    # Empty State Notice
    if overview["batch_count"] == 0 and overview["stored_alerts_count"] == 0:
        st.info(
            f"ℹ️ **No streaming data found** in database `{mongo_db_name}` matching the current filter.\n\n"
            "To generate data, start the pipeline:\n"
            "1. Produce records: `python producer.py --limit 60`\n"
            "2. Run consumer: `spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.6 spark_consumer.py`"
        )
        return

    # -------------------------------------------------------------------------
    # SECTION A: OVERVIEW
    # -------------------------------------------------------------------------
    st.subheader("1. Ingestion & Threat Overview")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Total Records Processed</div>
                <div class="metric-value">{overview['total_records']:,}</div>
                <div class="metric-sub">From {overview['total_batches']} micro-batch summaries</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Predicted Threat Alerts</div>
                <div class="metric-value" style="color: #f87171;">{overview['accumulated_alerts']:,}</div>
                <div class="metric-sub">Aggregated across micro-batches</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Predicted Normal Records</div>
                <div class="metric-value" style="color: #34d399;">{overview['accumulated_normal']:,}</div>
                <div class="metric-sub">Packets flagged as non-threat</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col4:
        alert_rate_str = f"{overview['overall_alert_rate'] * 100:.1f}%" if overview['overall_alert_rate'] is not None else "N/A"
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Overall Alert Rate</div>
                <div class="metric-value">{alert_rate_str}</div>
                <div class="metric-sub">Alerts / Total Processed Records</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col5:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-title">Persisted Alert Docs</div>
                <div class="metric-value" style="color: #38bdf8;">{overview['stored_alerts_count']:,}</div>
                <div class="metric-sub">In collection <code>threat_alerts</code></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown(
        """
        <div style="font-size: 0.8rem; color: #94a3b8; margin-top: -6px; margin-bottom: 20px;">
            📌 <em><b>Architecture Note:</b> Accumulated Batch Metrics represent the running cumulative record counts evaluated across Spark micro-batches.
            To conserve storage, only predicted threat packets (<code>predicted_attack == 1</code>) are persisted to the <code>threat_alerts</code> collection.</em>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # -------------------------------------------------------------------------
    # MAIN TABS
    # -------------------------------------------------------------------------
    tab_alerts, tab_perf, tab_batch, tab_health = st.tabs([
        "🚨 Threat Alerts Explorer",
        "🎯 Offline Ground-Truth Evaluation",
        "📊 Batch Lake Analytics & Historical Trends",
        "🩺 System Health & Disaster Recovery",
    ])

    # -------------------------------------------------------------------------
    # TAB 1: THREAT ALERTS EXPLORER
    # -------------------------------------------------------------------------
    with tab_alerts:
        st.subheader("Persisted Threat Alerts Browser")
        st.caption("Paginated inspection of alert documents stored in MongoDB collection `threat_alerts`.")

        col_f1, col_f2, col_f3, col_f4 = st.columns(4)
        with col_f1:
            proto_filter = st.selectbox("Protocol Filter", options=["All", "TCP", "UDP"], index=0)
        with col_f2:
            reason_filter = st.selectbox(
                "Triggered Rule / Reason",
                options=[
                    "All",
                    "RAPID_BURST_DELTA",
                    "KNOWN_ATTACK_ORIGIN_TTL",
                    "ANOMALOUS_LEN",
                    "OVERSIZED_MTU_LEN",
                    "HEADER_ONLY_TCP_LEN",
                    "INVALID_METADATA",
                ],
                index=0,
            )
        with col_f3:
            gt_filter = st.selectbox(
                "Ground Truth Filter",
                options=["All", "ATTACK (All attacks)", "BENIGN", "DDoS", "DoS Hulk", "PortScan"],
                index=0,
            )
        with col_f4:
            sort_by = st.selectbox(
                "Sort Field",
                options=["stored_at", "event_timestamp", "kafka_offset", "ttl", "total_len", "t_delta"],
                index=0,
            )

        col_p1, col_p2, col_p3 = st.columns([1, 1, 2])
        with col_p1:
            page_size = st.selectbox("Rows per page", options=[10, 25, 50, 100], index=1)
        with col_p2:
            page_num = st.number_input("Page", min_value=1, value=1, step=1)
        with col_p3:
            sort_order_str = st.radio("Sort Order", options=["Descending", "Ascending"], horizontal=True, index=0)
            sort_dir = -1 if sort_order_str == "Descending" else 1

        skip_count = (page_num - 1) * page_size
        alerts_data, total_alerts_match = get_filtered_alerts(
            db,
            run_id=selected_run,
            protocol=proto_filter,
            alert_reason=reason_filter,
            ground_truth=gt_filter,
            start_time=start_time_filter,
            end_time=end_time_filter,
            sort_field=sort_by,
            sort_direction=sort_dir,
            limit=page_size,
            skip=skip_count,
        )

        total_pages = max(1, (total_alerts_match + page_size - 1) // page_size)
        st.markdown(
            f"**Displaying:** Page `{page_num}` of `{total_pages}` (Total matching alerts: `{total_alerts_match:,}`)"
        )

        if alerts_data:
            display_rows = []
            for doc in alerts_data:
                # Format timestamps safely
                evt_time = doc.get("event_timestamp")
                evt_str = evt_time.strftime("%Y-%m-%d %H:%M:%S") if isinstance(evt_time, datetime) else "-"
                
                # Format delta safely
                td = doc.get("t_delta")
                td_str = f"{td:.6f}s" if td is not None else "-"

                display_rows.append({
                    "Alert ID": doc.get("_id"),
                    "Run ID": doc.get("run_id") or "Legacy / Unassigned",
                    "Event Timestamp": evt_str,
                    "Protocol": (doc.get("protocol") or "unknown").upper(),
                    "TTL": doc.get("ttl", "-"),
                    "Length (B)": doc.get("total_len", "-"),
                    "Delta (t_delta)": td_str,
                    "Alert Reasons": doc.get("alert_reason", "-"),
                    "Kafka Offset": doc.get("kafka_offset", "-"),
                    "Evaluation: Ground Truth": doc.get("ground_truth_label") or "Unlabelled",
                })

            df_alerts = pd.DataFrame(display_rows)
            st.dataframe(df_alerts, width="stretch", hide_index=True)
        else:
            st.info("No threat alerts match the selected filter criteria.")

    # -------------------------------------------------------------------------
    # TAB 2: OFFLINE GROUND-TRUTH EVALUATION
    # -------------------------------------------------------------------------
    with tab_perf:
        st.subheader("Offline Ground-Truth Detection Performance")
        st.markdown(
            """
            <div class="eval-banner">
                ⚠️ <b>Ground-Truth Isolation Notice:</b> In real-world streaming environments, packet labels are strictly unavailable.
                Labels in this pipeline are used <b>only</b> in the post-prediction offline evaluation layer to assess baseline detector efficacy.
                Zero labels are passed to or inspected by the heuristic detector.
            </div>
            """,
            unsafe_allow_html=True,
        )

        matrix = calculate_aggregate_confusion_matrix(batches)

        if matrix["has_eval_data"]:
            col_cm, col_metrics = st.columns([1, 1])

            # Confusion Matrix Table & Heatmap
            with col_cm:
                st.markdown("#### Summed Confusion Matrix")
                st.caption(f"Aggregated from {matrix['eval_batch_count']} evaluated micro-batches.")

                cm_z = [
                    [matrix["tp"], matrix["fp"]],
                    [matrix["fn"], matrix["tn"]],
                ]
                cm_text = [
                    [f"TP: {matrix['tp']:,}", f"FP: {matrix['fp']:,}"],
                    [f"FN: {matrix['fn']:,}", f"TN: {matrix['tn']:,}"],
                ]

                fig_cm = ff_confusion_matrix = go.Figure(
                    data=go.Heatmap(
                        z=cm_z,
                        x=["Actual Attack (1)", "Actual Benign (0)"],
                        y=["Predicted Alert (1)", "Predicted Normal (0)"],
                        text=cm_text,
                        texttemplate="%{text}",
                        textfont={"size": 16, "color": "white"},
                        colorscale=[[0, "#1e293b"], [0.5, "#2563eb"], [1, "#059669"]],
                        showscale=False,
                    )
                )
                fig_cm.update_layout(
                    margin=dict(t=30, b=30, l=30, r=30),
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#e2e8f0",
                    height=300,
                )
                st.plotly_chart(fig_cm, width="stretch")

            # Performance Metrics Cards
            with col_metrics:
                st.markdown("#### Classification Metrics")
                
                prec_str = f"{matrix['precision']:.4f}" if matrix["precision"] is not None else "N/A (Undefined)"
                rec_str = f"{matrix['recall']:.4f}" if matrix["recall"] is not None else "N/A (Undefined)"
                f1_str = f"{matrix['f1']:.4f}" if matrix["f1"] is not None else "N/A (Undefined)"
                fpr_str = f"{matrix['fpr']:.4f}" if matrix["fpr"] is not None else "N/A (Undefined)"
                acc_str = f"{matrix['accuracy']:.4f}" if matrix["accuracy"] is not None else "N/A (Undefined)"

                st.markdown(
                    f"""
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                        <div class="metric-card">
                            <div class="metric-title">Precision</div>
                            <div class="metric-value">{prec_str}</div>
                            <div class="metric-sub">TP / (TP + FP)</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-title">Recall (TPR)</div>
                            <div class="metric-value">{rec_str}</div>
                            <div class="metric-sub">TP / (TP + FN)</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-title">F1-Score</div>
                            <div class="metric-value">{f1_str}</div>
                            <div class="metric-sub">Harmonic Mean (P, R)</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-title">False Positive Rate</div>
                            <div class="metric-value">{fpr_str}</div>
                            <div class="metric-sub">FP / (FP + TN)</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.caption(f"Overall Classification Accuracy: **{acc_str}** | Total Evaluated: **{matrix['actual_attacks'] + matrix['actual_benign']:,}** records")

        else:
            st.info("No ground-truth evaluation metrics are available in the selected batches.")

    # -------------------------------------------------------------------------
    # TAB 3: BATCH LAKE ANALYTICS (Lambda batch layer -> serving layer)
    # -------------------------------------------------------------------------
    with tab_batch:
        render_batch_tab()

    # -------------------------------------------------------------------------
    # TAB 4: SYSTEM HEALTH & DISASTER RECOVERY
    # -------------------------------------------------------------------------
    with tab_health:
        render_health_tab()


def _dark_layout(fig, height=320):
    fig.update_layout(
        margin=dict(t=30, b=30, l=30, r=30), paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0", height=height,
    )
    return fig


def render_batch_tab():
    st.subheader("Batch Lake Analytics & Historical Trends")
    st.caption(
        "Lambda **batch layer**: Spark SQL over the immutable Parquet data lake (`batch_analytics.py`), "
        "pre-aggregated into MongoDB `historical_threat_rollups` (the serving layer). "
        "This tab reads those rollups only - no heavy scans at page-load time."
    )
    run = selected_run if selected_run != "All Runs" else None
    tumbling = get_historical_rollups(db, "tumbling_window", run)
    if not tumbling and not get_historical_rollups(db, "protocol_summary", run):
        st.info(
            "No batch rollups found yet. Run the batch layer after streaming:\n\n"
            "`python batch_analytics.py --lake-dir data/lake`"
        )
        return

    if tumbling:
        st.markdown("#### Tumbling vs Sliding Window Alert Trend")
        sliding = get_historical_rollups(db, "sliding_window", run)
        fig = go.Figure()
        fig.add_trace(go.Bar(x=[r["window_start"] for r in tumbling], y=[r["alerts"] for r in tumbling],
                             name="Alerts / tumbling window", marker_color="#3b82f6"))
        if sliding:
            fig.add_trace(go.Scatter(x=[r["window_start"] for r in sliding], y=[r["alerts"] for r in sliding],
                                     name="Alerts / sliding window", line=dict(color="#f87171")))
        st.plotly_chart(_dark_layout(fig), width="stretch")
        st.caption("Tumbling windows are non-overlapping (exact counts, higher latency to a new bucket); "
                   "sliding windows overlap (smoother trend, each event counted in several windows). "
                   "Time axis = Kafka ingestion timestamp.")

    col_a, col_b = st.columns(2)
    protocols = get_historical_rollups(db, "protocol_summary", run)
    with col_a:
        st.markdown("#### Top Attacked Protocols")
        if protocols:
            dfp = pd.DataFrame(protocols).groupby("protocol", as_index=False)[["events", "alerts"]].sum()
            dfp["alert_rate"] = (dfp["alerts"] / dfp["events"]).round(4)
            st.dataframe(dfp.sort_values("alerts", ascending=False), width="stretch", hide_index=True)
    with col_b:
        st.markdown("#### Payload Entropy Distribution")
        ent = get_historical_rollups(db, "entropy_hist", run)
        if ent:
            dfe = pd.DataFrame(ent).groupby("bin_low", as_index=False)[["benign", "attack"]].sum()
            fig_e = go.Figure()
            fig_e.add_trace(go.Bar(x=dfe["bin_low"], y=dfe["benign"], name="Benign", marker_color="#34d399"))
            fig_e.add_trace(go.Bar(x=dfe["bin_low"], y=dfe["attack"], name="Attack", marker_color="#f87171"))
            fig_e.update_layout(barmode="group", xaxis_title="Shannon entropy (bits)")
            st.plotly_chart(_dark_layout(fig_e), width="stretch")
        else:
            st.caption("Entropy needs payloads: produce with `--include-payload`.")

    families = get_historical_rollups(db, "attack_family", run)
    if families:
        st.markdown("#### Detection by Attack Family (post-hoc, ground truth)")
        dff = pd.DataFrame(families).groupby("label", as_index=False)[["events", "detected", "rule_detected"]].sum()
        dff["detection_rate"] = (dff["detected"] / dff["events"]).round(4)
        dff["rule_only_rate"] = (dff["rule_detected"] / dff["events"]).round(4)
        st.dataframe(dff.sort_values("events", ascending=False), width="stretch", hide_index=True)

    heat = get_historical_rollups(db, "hop_heatmap", run)
    if heat:
        st.markdown("#### Protocol x TTL-bucket Threat Heatmap")
        dfh = pd.DataFrame(heat).groupby(["protocol", "ttl_bucket"], as_index=False)[["events", "alerts"]].sum()
        dfh["alert_rate"] = dfh["alerts"] / dfh["events"]
        piv = dfh.pivot(index="protocol", columns="ttl_bucket", values="alert_rate")
        fig_h = go.Figure(go.Heatmap(z=piv.values, x=list(piv.columns), y=list(piv.index),
                                     colorscale="Reds", colorbar=dict(title="alert rate")))
        st.plotly_chart(_dark_layout(fig_h, 280), width="stretch")
        st.caption("TTL bucket is a network-distance proxy; the payload dataset has no IP addresses, so a true subnet heatmap is not derivable.")

    fmt = get_historical_rollups(db, "storage_format", run)
    if fmt:
        f = fmt[-1]
        st.markdown("#### Storage Format Study: CSV vs Parquet (Snappy)")
        st.markdown(
            f"CSV **{human_bytes(f['csv_bytes'])}** vs Parquet **{human_bytes(f['parquet_bytes'])}** "
            f"-> **{f['compression_ratio']}x** smaller; single-column scan "
            f"{f['csv_scan_seconds']}s (CSV) vs {f['parquet_scan_seconds']}s (Parquet)."
        )


def render_health_tab():
    st.subheader("System Health & Disaster Recovery")
    lake_dir = get_secret_setting("LAKE_DIR", "data/lake")
    backup_dir = get_secret_setting("BACKUP_DIR", "backups")
    bootstrap = get_secret_setting("KAFKA_BOOTSTRAP", "localhost:9092")
    topic = get_secret_setting("KAFKA_TOPIC", "network-records-multi")
    ckpt = get_secret_setting("CHECKPOINT_DIR", "checkpoints/stage8_lambda")

    lake = get_lake_stats(lake_dir)
    backup = get_backup_status(backup_dir)
    lag = get_kafka_consumer_lag(bootstrap, topic, ckpt) if bootstrap else {"available": False}

    c1, c2, c3 = st.columns(3)
    with c1:
        if backup["available"]:
            ts = backup["latest_time"].strftime("%Y-%m-%d %H:%M UTC")
            ok = {True: "verified", False: "VERIFY FAILED", None: "not verified"}[backup["latest_verified"]]
            body = (f"<div class='metric-value' style='font-size:1.2rem'>{ts}</div>"
                    f"<div class='metric-sub'>{ok} - {backup['count']} snapshots, {human_bytes(backup['total_bytes'])}</div>")
        else:
            body = "<div class='metric-value' style='font-size:1.2rem'>N/A</div><div class='metric-sub'>No snapshots on this host</div>"
        st.markdown(f"<div class='metric-card'><div class='metric-title'>Last Backup</div>{body}</div>", unsafe_allow_html=True)
    with c2:
        if lake["available"]:
            body = (f"<div class='metric-value'>{human_bytes(lake['bytes'])}</div>"
                    f"<div class='metric-sub'>{lake['files']:,} Parquet files (Snappy)</div>")
        else:
            body = "<div class='metric-value'>N/A</div><div class='metric-sub'>Lake not mounted on this host</div>"
        st.markdown(f"<div class='metric-card'><div class='metric-title'>Parquet Lake Size</div>{body}</div>", unsafe_allow_html=True)
    with c3:
        if lag.get("available"):
            per = ", ".join(f"p{p}:{v:,}" for p, v in sorted(lag["per_partition"].items()))
            body = (f"<div class='metric-value'>{lag['total']:,}</div>"
                    f"<div class='metric-sub'>{lag['partitions']} partitions ({per})</div>")
        else:
            body = f"<div class='metric-value'>N/A</div><div class='metric-sub'>Kafka unreachable ({lag.get('reason', 'n/a')})</div>"
        st.markdown(f"<div class='metric-card'><div class='metric-title'>Kafka Consumer Lag</div>{body}</div>", unsafe_allow_html=True)
    cluster = get_cluster_status(mongo_uri)
    if cluster["available"]:
        icon = {"PRIMARY": "🟢", "SECONDARY": "🔵", "ARBITER": "⚪"}
        kind = "Sharded cluster (via mongos)" if cluster["sharded"] else "Replica set"
        st.markdown(f"**MongoDB data tier: {kind}**")
        rows = []
        for shard, rs in cluster["shards"].items():
            for m in rs.get("members", []):
                rows.append({"Shard / Set": shard, "Node": m["name"],
                             "Role": f"{icon.get(m['state'], '🔴')} {m['state']}", "Healthy": m["healthy"]})
        if rows:
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    else:
        st.caption("Shard / replication status unavailable (standalone MongoDB or restricted account).")
    st.caption("Lag = Kafka log-end offset minus the offset in the Spark checkpoint. "
               "Cards degrade to N/A on Streamlit Cloud where Kafka, the lake and backups are not local - no secrets required.")


# Render dashboard within Streamlit
render_dashboard_content()
