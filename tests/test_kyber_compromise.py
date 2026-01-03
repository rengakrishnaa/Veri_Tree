import requests, json, os, time

URL = "http://localhost:5000/run"
OUT_DIR = "outputs"
os.makedirs(OUT_DIR, exist_ok=True)

def run_compromise_test(compromised_family=None):
    payload = {
        "admin_name": "admin",
        "n_moderators": 4,
        "members_per_mod": 3,
        "kem_algs": ["Kyber512", "Saber", "NTRU"],
        "compromised_family": compromised_family,  # e.g., "Kyber512"
    }

    t0 = time.time()
    response = requests.post(URL, json=payload)
    dt = round((time.time() - t0) * 1000, 2)

    result = response.json()
    result["runtime_ms"] = dt
    result["compromised_family"] = compromised_family or "None"

    fname = f"kyber_compromise_{compromised_family or 'none'}.json"
    json.dump(result, open(os.path.join(OUT_DIR, fname), "w"), indent=2)
    print(f"✅ Completed test: {compromised_family or 'None'} compromised")

if __name__ == "__main__":
    print("🧬 Running Multi-KEM Resilience Tests")
    run_compromise_test(None)
    run_compromise_test("Kyber512")
    run_compromise_test("Saber")
    print("\n✅ Done. Check outputs/ for JSON logs.")
