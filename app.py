
import time
import streamlit as st

from monitor import (
    get_system_info,
    get_cpu_info,
    get_memory_info,
    get_disk_info,
    get_network_info,
    get_top_processes,
    get_temperature_info,
    get_listening_ports,
)
from security_logger import log_security_event, get_recent_events


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="System Health & Security Center",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
        [data-testid="stAppViewContainer"] {
            background-color: #0b1120;
        }
        [data-testid="stMainBlockContainer"] {
            padding-top: 2rem;
            padding-bottom: 3rem;
            max-width: 1500px;
        }
        [data-testid="stSidebar"] {
            background-color: #111827;
            border-right: 1px solid #263449;
        }
        h1, h2, h3 {
            color: #e5edf8;
            letter-spacing: -0.4px;
        }
        [data-testid="stCaptionContainer"] {
            color: #94a3b8;
        }
        [data-testid="stMetric"] {
            background-color: #111c2e;
            border: 1px solid #263449;
            padding: 18px;
            border-radius: 12px;
        }
        [data-testid="stMetricLabel"] {
            color: #a8b7cc;
        }
        [data-testid="stMetricValue"] {
            color: #f1f5f9;
        }
        [data-testid="stExpander"] {
            background-color: #111827;
            border: 1px solid #263449;
            border-radius: 10px;
        }
        [data-testid="stDataFrame"] {
            border: 1px solid #263449;
            border-radius: 10px;
            overflow: hidden;
        }
        .stButton > button,
        .stDownloadButton > button {
            border-radius: 8px;
            font-weight: 600;
            border: 1px solid #3b82f6;
        }
        hr {
            border-color: #263449;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# SIDEBAR NAVIGATION AND SETTINGS
# --------------------------------------------------

st.sidebar.title("🛡️ Control Center")
st.sidebar.caption("Linux monitoring and defensive security")

page = st.sidebar.radio(
    "Navigation",
    [
        "Overview",
        "Performance",
        "Processes & Hardware",
        "Network Security",
        "Event Center",
    ],
)

st.sidebar.divider()
st.sidebar.subheader("Alert Thresholds")

cpu_warning = st.sidebar.slider(
    "CPU warning (%)", 50, 100, 85
)
memory_warning = st.sidebar.slider(
    "RAM warning (%)", 50, 100, 85
)
disk_warning = st.sidebar.slider(
    "Disk warning (%)", 50, 100, 90
)

st.sidebar.info(
    "Alerts flag conditions for review. They do not prove "
    "that a system has been compromised."
)
st.sidebar.caption("Live monitoring refreshes approximately every 3 seconds.")


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.title("🛡️ System Health & Security Center")
st.caption(
    "LINUX MONITORING  /  PERFORMANCE  /  DEFENSIVE SECURITY"
)


# --------------------------------------------------
# HELPER
# --------------------------------------------------

def gib(value):
    return f"{value / (1024 ** 3):.2f} GiB"


# --------------------------------------------------
# LIVE MONITORING
# --------------------------------------------------

@st.fragment(run_every="3s")
def live_monitor(selected_page):

    cpu = get_cpu_info()
    memory = get_memory_info()
    disk = get_disk_info("/")
    network = get_network_info()

    cpu_percent = cpu["usage_percent"]
    memory_percent = memory["percent"]
    disk_percent = disk["percent"]

    # Historical samples are stored for this session.
    if "metric_history" not in st.session_state:
        st.session_state["metric_history"] = []

    history = st.session_state["metric_history"]
    history.append({
        "time": time.strftime("%H:%M:%S"),
        "CPU (%)": cpu_percent,
        "RAM (%)": memory_percent,
        "Disk (%)": disk_percent,
    })
    st.session_state["metric_history"] = history[-60:]

    # Calculate network throughput from successive samples.
    now = time.monotonic()
    previous = st.session_state.get("network_sample")

    upload_rate = None
    download_rate = None

    if previous is not None:
        elapsed = now - previous["time"]

        if elapsed > 0:
            upload_rate = max(
                0, network["bytes_sent"] - previous["sent"]
            ) / elapsed

            download_rate = max(
                0, network["bytes_received"] - previous["received"]
            ) / elapsed

    st.session_state["network_sample"] = {
        "time": now,
        "sent": network["bytes_sent"],
        "received": network["bytes_received"],
    }

    # Evaluate resource thresholds on every fragment refresh.
    current_alerts = {}

    if cpu_percent >= cpu_warning:
        current_alerts["cpu"] = (
            f"High CPU usage: {cpu_percent:.1f}% "
            f"(threshold {cpu_warning}%)."
        )

    if memory_percent >= memory_warning:
        current_alerts["memory"] = (
            f"High RAM usage: {memory_percent:.1f}% "
            f"(threshold {memory_warning}%)."
        )

    if disk_percent >= disk_warning:
        current_alerts["disk"] = (
            f"High root filesystem usage: {disk_percent:.1f}% "
            f"(threshold {disk_warning}%)."
        )

    previous_alerts = st.session_state.get(
        "active_resource_alerts", {}
    )

    for key, message in current_alerts.items():
        if key not in previous_alerts:
            log_security_event(message, level="WARNING")

    for key, message in previous_alerts.items():
        if key not in current_alerts:
            log_security_event(
                f"RESOLVED: {message}",
                level="INFO",
            )

    st.session_state["active_resource_alerts"] = current_alerts

    # Observe listening sockets on every refresh.
    listeners = get_listening_ports()

    exposed = [
        item for item in listeners
        if item.get("exposure") == "All interfaces"
    ]

    current_exposure = {
        (
            item.get("protocol", "Unknown"),
            item.get("address", "Unknown"),
            item.get("port", 0),
            item.get("pid"),
        )
        for item in exposed
    }

    previous_exposure = st.session_state.get(
        "active_exposure", set()
    )

    for protocol, address, port, pid in (
        current_exposure - previous_exposure
    ):
        log_security_event(
            f"Socket bound to all interfaces: "
            f"{protocol} {address}:{port}, PID={pid}",
            level="WARNING",
        )

    for protocol, address, port, pid in (
        previous_exposure - current_exposure
    ):
        log_security_event(
            f"RESOLVED: Socket no longer observed: "
            f"{protocol} {address}:{port}, PID={pid}",
            level="INFO",
        )

    st.session_state["active_exposure"] = current_exposure

    # --------------------------------------------------
    # OVERVIEW PAGE
    # --------------------------------------------------

    if selected_page == "Overview":
        st.header("📊 System Overview")

        c1, c2, c3 = st.columns(3)

        c1.metric("CPU Usage", f"{cpu_percent:.1f}%")
        c1.progress(max(0, min(100, int(cpu_percent))))

        c2.metric("RAM Usage", f"{memory_percent:.1f}%")
        c2.progress(max(0, min(100, int(memory_percent))))

        c3.metric("Disk Usage (/)", f"{disk_percent:.1f}%")
        c3.progress(max(0, min(100, int(disk_percent))))

        c1, c2, c3 = st.columns(3)
        c1.metric("RAM Available", gib(memory["available"]))
        c2.metric("Disk Free", gib(disk["free"]))
        c3.metric("Logical CPU Cores", cpu["logical_cores"])

        st.divider()
        st.subheader("Resource Health Alerts")

        if current_alerts:
            for message in current_alerts.values():
                st.warning(message)
        else:
            st.success("No configured resource thresholds exceeded.")

        st.subheader("Network Activity")

        n1, n2 = st.columns(2)

        if download_rate is None:
            n1.metric("Download Rate", "Sampling...")
            n2.metric("Upload Rate", "Sampling...")
        else:
            n1.metric(
                "Download Rate",
                f"{download_rate / 1024:.1f} KiB/s",
            )
            n2.metric(
                "Upload Rate",
                f"{upload_rate / 1024:.1f} KiB/s",
            )

        st.caption(
            f"Total received: {gib(network['bytes_received'])} • "
            f"Total sent: {gib(network['bytes_sent'])}"
        )

        system = get_system_info()

        with st.expander("System Information", expanded=False):
            c1, c2 = st.columns(2)
            c1.write(f"**Hostname:** {system.get('hostname', 'Unknown')}")
            c1.write(f"**Operating system:** {system.get('os', 'Unknown')}")
            c2.write(f"**Kernel:** {system.get('kernel', 'Unknown')}")
            c2.write(f"**Architecture:** {system.get('architecture', 'Unknown')}")

    # --------------------------------------------------
    # PERFORMANCE PAGE
    # --------------------------------------------------

    elif selected_page == "Performance":
        st.header("📈 Performance Monitoring")

        c1, c2, c3 = st.columns(3)
        c1.metric("CPU", f"{cpu_percent:.1f}%")
        c2.metric("RAM", f"{memory_percent:.1f}%")
        c3.metric("Disk", f"{disk_percent:.1f}%")

        st.subheader("Recent Performance History")
        st.caption(
            "Latest 60 samples in this dashboard session; "
            "history is not saved permanently."
        )

        st.line_chart(
            st.session_state["metric_history"],
            x="time",
            y=["CPU (%)", "RAM (%)", "Disk (%)"],
        )

        st.subheader("Network Throughput")

        n1, n2 = st.columns(2)

        if download_rate is None:
            n1.metric("Download", "Sampling...")
            n2.metric("Upload", "Sampling...")
        else:
            n1.metric("Download", f"{download_rate / 1024:.1f} KiB/s")
            n2.metric("Upload", f"{upload_rate / 1024:.1f} KiB/s")

        st.caption(
            f"Received total: {gib(network['bytes_received'])} • "
            f"Sent total: {gib(network['bytes_sent'])}"
        )

        if cpu.get("load_average") is not None:
            loads = cpu["load_average"]
            st.info(
                f"Load average (1 / 5 / 15 min): "
                f"{loads[0]:.2f} / {loads[1]:.2f} / {loads[2]:.2f}"
            )

    # --------------------------------------------------
    # PROCESSES AND HARDWARE PAGE
    # --------------------------------------------------

    elif selected_page == "Processes & Hardware":
        st.header("⚙️ Processes & Hardware")

        st.subheader("Top Processes by CPU Usage")
        processes = get_top_processes(limit=10)

        if processes:
            st.dataframe(
                processes,
                column_order=[
                    "pid",
                    "name",
                    "username",
                    "cpu_percent",
                    "memory_percent",
                    "status",
                ],
                column_config={
                    "pid": st.column_config.NumberColumn("PID"),
                    "name": "Process",
                    "username": "User",
                    "cpu_percent": st.column_config.NumberColumn(
                        "CPU %", format="%.1f"
                    ),
                    "memory_percent": st.column_config.NumberColumn(
                        "RAM %", format="%.2f"
                    ),
                    "status": "Status",
                },
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No accessible processes were returned.")

        st.divider()
        st.subheader("Hardware Temperatures")
        temperatures = get_temperature_info()

        if temperatures:
            st.dataframe(
                temperatures,
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info(
                "No temperature sensors reported. This is common "
                "on virtual machines or unsupported hardware."
            )

        system = get_system_info()

        with st.expander("System Details"):
            st.json(system)

    # --------------------------------------------------
    # NETWORK SECURITY PAGE
    # --------------------------------------------------

    elif selected_page == "Network Security":
        st.header("🔌 Network Security")
        st.caption(
            "Review listening sockets and their local binding addresses."
        )

        if listeners:
            st.dataframe(
                listeners,
                column_config={
                    "protocol": "Protocol",
                    "address": "Local Address",
                    "port": st.column_config.NumberColumn("Port"),
                    "exposure": "Binding / Exposure",
                    "pid": st.column_config.NumberColumn("Process ID"),
                    "process": "Process Name",
                },
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info(
                "No matching sockets were returned, or access was "
                "restricted. Compare with `ss -lntup` if needed."
            )

        if exposed:
            st.warning(
                f"{len(exposed)} socket(s) are bound to all interfaces. "
                "Review whether each service needs this binding."
            )
            st.caption(
                "A wildcard binding does not prove internet reachability. "
                "Firewalls and service configuration also affect access."
            )
        elif listeners:
            st.success(
                "No sockets bound to all interfaces were found "
                "in the collected results."
            )

        st.caption(
            "These are review indicators, not proof of compromise."
        )

    st.caption("Live monitoring refreshes approximately every 3 seconds.")


# --------------------------------------------------
# RENDER SELECTED PAGE
# --------------------------------------------------

live_monitor(page)


# --------------------------------------------------
# EVENT CENTER
# --------------------------------------------------

if page == "Event Center":
    st.header("🛡️ Security Event Center")
    st.caption("Recent locally recorded security events.")

    events = get_recent_events(limit=100)

    info_count = sum("INFO" in event for event in events)
    warning_count = sum("WARNING" in event for event in events)
    error_count = sum("ERROR" in event for event in events)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Events", len(events))
    c2.metric("Info", info_count)
    c3.metric("Warnings", warning_count)
    c4.metric("Errors", error_count)

    st.divider()
    st.subheader("Recent Events")

    event_filter = st.selectbox(
        "Filter by severity",
        ["All Events", "INFO", "WARNING", "ERROR"],
    )

    if st.button("Refresh event log"):
        st.rerun()

    if events:
        if event_filter == "All Events":
            filtered_events = events
        else:
            filtered_events = [
                event for event in events
                if event_filter in event
            ]

        st.caption(
            f"Showing {len(filtered_events)} of {len(events)} recent events."
        )

        st.download_button(
            label="Download Filtered Security Report",
            data="\n".join(filtered_events),
            file_name="security_event_report.txt",
            mime="text/plain",
        )

        if filtered_events:
            st.code("\n".join(filtered_events), language="text")
        else:
            st.info("No events match this filter.")
    else:
        st.info(
            "No events logged yet. Events appear when a monitored "
            "warning first occurs or clears."
        )
else:
    st.caption("Open Event Center in the sidebar to review security logs.")

