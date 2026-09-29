import joblib
pkl = joblib.load("models/preprocessing_unsw.pkl")
print("Feature names:", pkl.get("feature_names"))
for k, v in pkl["label_encoders"].items():
    print(f"Encoder {k}: {len(v.classes_)} classes -> {list(v.classes_)[:5]}")
