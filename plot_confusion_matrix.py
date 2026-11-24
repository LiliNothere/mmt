import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

# 1. Load dataset
df = pd.read_csv("data/FlowStatsfile.csv")

# 2. Load model package
model_data = joblib.load("models/randomforest_model.joblib")

# 3. Lấy Pipeline và danh sách feature
model = model_data["model"]
feature_columns = model_data["feature_columns"]

print("Model type:", model_data["model_type"])
print("Training accuracy:", model_data["accuracy"])
print("Number of features:", len(feature_columns))

# 4. Kiểm tra cột dữ liệu
target_column = "label"

if target_column not in df.columns:
    raise ValueError(f"Không tìm thấy cột nhãn: {target_column}")

missing = [c for c in feature_columns if c not in df.columns]
if missing:
    raise ValueError(f"Dataset thiếu các feature: {missing}")

# 5. Tách dữ liệu
X = df[feature_columns]
y = df[target_column]

# 6. Chia tập kiểm thử
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# 7. Dự đoán
y_pred = model.predict(X_test)

# 8. Tạo Confusion Matrix
labels = model.classes_

cm = confusion_matrix(y_test, y_pred, labels=labels)

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=labels
)

disp.plot(cmap="Blues", values_format="d")

plt.title("Confusion Matrix - Random Forest")
plt.tight_layout()

# 9. Xuất ảnh
output_file = "random_forest_confusion_matrix.png"
plt.savefig(output_file, dpi=300, bbox_inches="tight")

print("Confusion Matrix:")
print(cm)
print(f"Da xuat anh: {output_file}")

plt.show()



