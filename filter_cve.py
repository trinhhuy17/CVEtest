import pandas as pd
import os
import sys

# Đọc file CSV đầu vào từ dòng lệnh
input_file = sys.argv[1]
print(f"👉 Đang xử lý: {input_file}")

# Tạo thư mục kết quả
output_dir = "filtered"
os.makedirs(output_dir, exist_ok=True)

# Đọc dữ liệu
df = pd.read_csv(input_file)

# Trích năm từ CVE ID
df['Year'] = df['CVE'].str.extract(r'CVE-(\d{4})-')

# Danh sách năm và severity cần xử lý
target_years = ['2016', '2019', '2022']
severities = ['High', 'Critical']

# Ghi file cho mỗi tổ hợp
for year in target_years:
    for severity in severities:
        subset = df[(df['Year'] == year) & (df['Severity'] == severity)]
        out_file = f"{output_dir}/cve_{severity.lower()}_{year}.csv"
        subset.to_csv(out_file, index=False)
        print(f"✅ {out_file} ({len(subset)} dòng)")
