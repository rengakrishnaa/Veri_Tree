import requests, json, time, os, csv

URL = "http://localhost:5000/run"
OUT_DIR = "outputs"
os.makedirs(OUT_DIR, exist_ok=True)

configs = [
    (2, 2),
    (4, 4),
    (6, 8),
    (8, 10),
]

records = []

for mods, members in configs:
    print(f"⏱ Running benchmark: {mods} mods × {members} members/mod")
    payload = {
        "admin_name": "admin",
        "n_moderators": mods,
        "members_per_mod": members,
        "kem_algs": ["Kyber512"],
    }

    t0 = time.time()
    response = requests.post(URL, json=payload)
    dt = round((time.time() - t0) * 1000, 2)
    data = response.json()

    records.append({
        "moderators": mods,
        "members_per_mod": members,
        "total_nodes": 1 + mods + (mods * members),
        "runtime_ms": dt,
        "bytes_sent": len(json.dumps(data)),
        "unanimous": data.get("unanimous"),
    })

with open(os.path.join(OUT_DIR, "benchmark_scaling.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=records[0].keys())
    writer.writeheader()
    writer.writerows(records)

print("\n📊 Benchmark complete → outputs/benchmark_scaling.csv")
