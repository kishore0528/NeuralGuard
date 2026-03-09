import pandas as pd
import tensorflow as tf
import joblib
import os

# Load model and scaler once
MODEL_PATH = os.path.join(os.path.dirname(__file__), "packet_model.keras")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.pkl")

model = None
scaler = None

if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
    model = tf.keras.models.load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

def predict_packet(window_size, src_port, flow_duration, total_fwd, total_bwd):
    """
    Predicts if a packet is malicious based on 5 features.
    Returns (verdict, confidence).
    Verdict: 1 (Malicious) if confidence > 0.65, else 0 (Benign).
    """
    if model is None or scaler is None:
        return 0, 0.0

    # Match exactly the column names and order used during training
    feature_names = ['Destination Port', 'Init_Win_bytes_forward', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']
    
    # Format into DataFrame
    data = pd.DataFrame([[src_port, window_size, flow_duration, total_fwd, total_bwd]], columns=feature_names)

    # Scale the data
    scaled_data = scaler.transform(data)

    # Predict
    prediction = model.predict(scaled_data, verbose=0)
    confidence = float(prediction[0][0])
    
    # Verdict based on 0.65 threshold
    verdict = 1 if confidence > 0.65 else 0
    
    return verdict, confidence
