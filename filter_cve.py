import pandas as pd
import os
import sys

# File đầu vào từ dòng lệnh
input_file = sys.argv[1]
print(f"👉 Đang xử lý file: {input_file}")

# Tạo thư mục output
output_dir = "filtered"
os.makedirs(output_dir, exist_ok=True)

# Đọc dữ liệu
df = pd.read_csv(input_file)

# Cột bắt buộc
expected_columns = [
    "CVE", "Title", "Server", "Severity", "BaseScore",
    "TemporalScore", "KB", "FixedBuild", "RestartRequired"
]

# Kiểm tra thiếu cột
missing_cols = [col for col in expected_columns if col not in df.columns]
if missing_cols:
    raise ValueError(f"⛔ File thiếu các cột sau: {missing_cols}")

# Danh sách Server cần lọc
servers = {
    "Windows Server 2016": "windows_2016",
    "Windows Server 2019": "windows_2019",
    "Windows Server 2022": "windows_2022"
}

severities = ["High", "Critical"]

# Lọc và xuất từng file
for server_name, server_key in servers.items():
    for severity in severities:
        subset = df[(df["Server"] == server_name) & (df["Severity"] == severity)]
        out_file = f"{output_dir}/cve_{severity.lower()}_{server_key}.csv"

        if not subset.empty:
            subset = subset[expected_columns]
            subset.to_csv(out_file, index=False)
            print(f"✅ Ghi {out_file} ({len(subset)} dòng)")
        else:
            print(f"⚠️ Không có dòng nào cho {server_name} - {severity}")
