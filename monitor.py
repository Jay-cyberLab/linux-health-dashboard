
import psutil
import platform
import time
import socket

def get_system_info():
    """Return basic information about this machine."""
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
    }


def get_cpu_info():
    """Collect CPU utilization and load averages."""
    result = {
        "usage_percent": psutil.cpu_percent(interval=0.2),
        "logical_cores": psutil.cpu_count(logical=True) or 1,
        "load_average": None,
    }

    # Load averages are available on Linux and other Unix-like systems.
    if hasattr(psutil, "getloadavg"):
        result["load_average"] = psutil.getloadavg()

    return result


def get_memory_info():
    """Collect physical RAM statistics."""
    mem = psutil.virtual_memory()

    return {
        "total": mem.total,
        "used": mem.used,
        "available": mem.available,
        "percent": mem.percent,
    }


def get_disk_info(path="/"):
    """Collect storage usage for the filesystem containing path."""
    disk = psutil.disk_usage(path)

    return {
        "total": disk.total,
        "used": disk.used,
        "free": disk.free,
        "percent": disk.percent,
    }


def get_network_info():
    """Collect cumulative network traffic counters."""
    counters = psutil.net_io_counters()

    return {
        "bytes_sent": counters.bytes_sent,
        "bytes_received": counters.bytes_recv,
        "packets_sent": counters.packets_sent,
        "packets_received": counters.packets_recv,
    }


def get_top_processes(limit=10):
    """Return processes using the most CPU at collection time."""
    processes = []

    # Prime CPU counters before measuring process CPU usage.
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    time.sleep(0.15)

    for proc in psutil.process_iter(
        ["pid", "name", "username", "memory_percent", "status"]
    ):
        try:
            info = proc.info
            info["cpu_percent"] = proc.cpu_percent(interval=None)
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return sorted(
        processes,
        key=lambda item: item.get("cpu_percent") or 0,
        reverse=True,
    )[:limit]


def get_temperature_info():
    """Read available hardware temperature sensors, if supported."""
    try:
        sensors = psutil.sensors_temperatures(fahrenheit=False)
    except (AttributeError, OSError):
        return []

    readings = []

    for sensor_name, entries in sensors.items():
        for entry in entries:
            if entry.current is not None:
                readings.append({
                    "sensor": entry.label or sensor_name,
                    "temperature_c": entry.current,
                })

    return readings


def get_listening_ports():
    """Return TCP listeners and UDP sockets bound to local addresses."""
    results = []

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return results

    for conn in connections:
        if not conn.laddr:
            continue

        # Use socket constants instead of psutil constants.
        if conn.type == socket.SOCK_STREAM:
            if conn.status != psutil.CONN_LISTEN:
                continue
            protocol = "TCP"

        elif conn.type == socket.SOCK_DGRAM:
            protocol = "UDP"

        else:
            continue

        address = conn.laddr.ip
        port = conn.laddr.port

        if address in ("127.0.0.1", "::1"):
            exposure = "Loopback only"
        elif address in ("0.0.0.0", "::"):
            exposure = "All interfaces"
        else:
            exposure = "Specific address"

        process_name = "Unavailable"

        if conn.pid is not None:
            try:
                process_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        results.append({
            "protocol": protocol,
            "address": address,
            "port": port,
            "exposure": exposure,
            "pid": conn.pid,
            "process": process_name,
        })

    return sorted(
        results,
        key=lambda item: (
            item["port"],
            item["protocol"],
            item["address"],
        ),
    )

