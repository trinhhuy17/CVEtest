import pandas as pd
import os
import sys

# Lấy tên file CSV từ dòng lệnh
input_file = sys.argv[1]
print(f"👉 Đang xử lý file: {input_file}")

# Tạo thư mục output nếu chưa có
output_dir = "filtered"
os.makedirs(output_dir, exist_ok=True)

# Đọc dữ liệu
df = pd.read_csv(input_file)

# Xác định cột chuẩn cần có
expected_columns = [
    "CVE", "Title", "Server", "Severity",
    "BaseScore", "TemporalScore", "KB",
    "FixedBuild", "RestartRequired", "Year"
]

# Kiểm tra thiếu cột
missing_cols = [col for col in expected_columns if col not in df.columns]
if missing_cols:
    raise ValueError(f"⛔ File thiếu các cột sau: {missing_cols}")

# Trích năm từ CVE nếu cột Year bị rỗng
if df["Year"].isnull().all():
    df["Year"] = df["CVE"].str.extract(r"CVE-(\d{4})")

# Lọc theo năm & mức độ
target_years = ['2016', '2019', '2022']
severities = ['High', 'Critical']

for year in target_years:
    for severity in severities:
        subset = df[
            (df["Year"].astype(str) == year) &
            (df["Severity"] == severity)
        ]

        # Ghi đúng thứ tự cột
        subset = subset[expected_columns]

        out_file = f"{output_dir}/cve_{severity.lower()}_{year}.csv"
        if not subset.empty:
            subset.to_csv(out_file, index=False)
            print(f"✅ Ghi {out_file} ({len(subset)} dòng)")
        else:
            print(f"⚠️ Không có dữ liệu cho {severity} - {year}")
