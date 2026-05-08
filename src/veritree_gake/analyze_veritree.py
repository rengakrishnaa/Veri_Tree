import csv
from pathlib import Path


def analyze_summary(path="veritree-repeated-stats.csv"):
    path = Path(path)

    if not path.exists():
        print(f"File not found: {path}")
        return

    rows = []
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    if not rows:
        print("CSV is empty.")
        return

    print("Fields:", rows[0].keys())

    if "metric" not in rows[0] or "value" not in rows[0]:
        print("Unexpected CSV format. Expected columns: metric, value")
        return

    metrics = {row["metric"]: row["value"] for row in rows}

    print("\nParsed summary:")
    print("-" * 40)

    unanimous = metrics.get("unanimous", "N/A")
    total_bytes = int(float(metrics.get("totalbytes", 0)))
    bandwidth_kb = float(metrics.get("bandwidthkb", 0.0))
    theoretical_bandwidth_kb = float(metrics.get("theoreticalbandwidthkb", 0.0))
    mkem_mode = metrics.get("mkemmode", "N/A")
    network_latency_ms = float(metrics.get("networklatencyms", 0.0))
    packet_loss = float(metrics.get("packetloss", 0.0))
    memory_per_node_bytes = int(float(metrics.get("memorypernodebytesest", 0)))
    energy_mj = float(metrics.get("energymjest", 0.0))

    print(f"Unanimous: {unanimous}")
    print(f"Total bandwidth: {total_bytes} bytes ({bandwidth_kb:.2f} KB)")
    print(f"Theoretical bandwidth: {theoretical_bandwidth_kb:.2f} KB")
    print(f"MKEM mode: {mkem_mode}")
    print(f"Network latency: {network_latency_ms:.2f} ms")
    print(f"Packet loss: {packet_loss:.4f}")
    print(f"Estimated memory per node: {memory_per_node_bytes} bytes")
    print(f"Estimated energy: {energy_mj:.3f} mJ")

    print("\nPhase timings (ms):")
    print("-" * 40)
    phase_metrics = {
        k.replace("phase_", "", 1): float(v)
        for k, v in metrics.items()
        if k.startswith("phase_")
    }

    if phase_metrics:
        for phase_name, phase_time in sorted(phase_metrics.items()):
            print(f"{phase_name}: {phase_time:.3f} ms")
    else:
        print("No phase timing entries found.")

    print("\nCPU operation counts:")
    print("-" * 40)
    cpu_metrics = {
        k.replace("cpu_", "", 1): int(float(v))
        for k, v in metrics.items()
        if k.startswith("cpu_")
    }

    if cpu_metrics:
        for op_name, op_count in sorted(cpu_metrics.items()):
            print(f"{op_name}: {op_count}")
    else:
        print("No CPU metrics found.")


if __name__ == "__main__":
    analyze_summary("veritree_benchmark_fixed_summary.csv")