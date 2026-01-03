import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv(r"E:\downloads\veritree_app\experiments\results.csv")

plt.plot(df["moderators"] * df["members"], df["runtime_ms"], marker='o')
plt.title("VeriTree-GAKE Scalability")
plt.xlabel("Total Group Size")
plt.ylabel("Runtime (ms)")
plt.grid(True)
plt.show()
