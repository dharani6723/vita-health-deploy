import tensorflow as tf
import numpy as np
import cv2
import pandas as pd
import json
import os

# === Load class indices (disease label mapping) ===
def load_class_indices(json_path):
    with open(json_path, "r") as f:
        return json.load(f)

# === Load vitamin deficiency mapping ===
def load_mapping(csv_file):
    df = pd.read_csv(csv_file)
    expected_cols = ["Diseases", "Deficiency"]
    if list(df.columns) != expected_cols:
        raise ValueError(f"Invalid CSV format. Expected {expected_cols}, got {list(df.columns)}")
    return {row["Diseases"].strip().lower(): row["Deficiency"].strip() for _, row in df.iterrows()}

# === Load trained model ===
def load_vitamin_model(model_path):
    try:
        model = tf.keras.models.load_model(model_path)
        print("✅ Model loaded successfully.")
        return model
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return None

# === Preprocess uploaded image ===
def preprocess_image(image_path):
    image = cv2.imread(image_path)
    image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    image = cv2.resize(image, (224, 224))
    image = image / 255.0
    return np.expand_dims(image, axis=0)

# === Predict disease ===
def predict_disease(model, class_indices, image_path):
    img = preprocess_image(image_path)
    preds = model.predict(img)
    predicted_index = np.argmax(preds, axis=1)[0]
    class_labels = list(class_indices.keys())
    predicted_class = class_labels[predicted_index]
    confidence = float(np.max(preds))
    return predicted_class, confidence

# === Wrapper for final output ===
def predict_vitamin_deficiency(model, class_indices, mapping, image_path):
    predicted_disease, confidence = predict_disease(model, class_indices, image_path)
    mapped_deficiency = mapping.get(predicted_disease.lower(), "No mapping found")
    return {
        "predicted_disease": predicted_disease,
        "mapped_deficiency": mapped_deficiency,
        "confidence": confidence
    }
