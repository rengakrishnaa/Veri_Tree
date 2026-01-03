from veritree_core import VeriTreeSimulator
import csv, time

def run_correctness_tests():
    sim = VeriTreeSimulator()
    results = []
    for mods in [1, 2, 4]:
        for members in [2, 3, 5]:
            start = time.time()
            data = sim.run_demo_tree("admin", mods, members, ["Kyber-512"])
            end = time.time()
            results.append({
                "moderators": mods,
                "members": members,
                "unanimous": data["unanimous"],
                "runtime_ms": round((end - start) * 1000, 2),
            })
    with open("experiments/results.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print("✅ Results saved to experiments/results.csv")

if __name__ == "__main__":
    run_correctness_tests()
