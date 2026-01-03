import requests, json, os, time

URL = "http://localhost:5000/run"
OUT_DIR = "outputs"
os.makedirs(OUT_DIR, exist_ok=True)

def log(title, content):
    print(f"\n--- {title} ---")
    print(content)

def run_case(description, mods, members, fail_node=None, equivocate=False):
    data = {
        "admin_name": "admin",
        "n_moderators": mods,
        "members_per_mod": members,
        "kem_algs": ["Kyber512", "Saber"],
        "simulate_fail_node": fail_node,
        "equivocate": equivocate,
    }

    log("Running", description)
    t0 = time.time()
    response = requests.post(URL, json=data)
    dt = round((time.time() - t0) * 1000, 2)

    result = response.json()
    result["runtime_ms"] = dt
    result["description"] = description

    out_path = os.path.join(OUT_DIR, f"{description.replace(' ','_')}.json")
    json.dump(result, open(out_path, "w"), indent=2)
    log("Saved result", out_path)
    return result


if __name__ == "__main__":
    print("🧪 Selective-Abort / Equivocation Tests")

    # Case 1: Normal baseline
    run_case("baseline", mods=3, members=2)

    # Case 2: One moderator fails to open mask
    run_case("mod2_fail_open", mods=3, members=2, fail_node="mod2")

    # Case 3: One moderator equivocates (different openings)
    run_case("mod2_equivocate", mods=3, members=2, fail_node="mod2", equivocate=True)

    print("\n✅ All tests completed. Check outputs/*.json for transcripts.")
