import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
import joblib
import os

def train_neural_guard():
    # Load dataset
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_path = os.path.abspath(os.path.join(script_dir, "..", "data", "Tuesday-WorkingHours.pcap_ISCX.csv"))
    if not os.path.exists(data_path):
        print(f"Dataset not found at {data_path}")
        return

    print("Loading dataset...")
    df = pd.read_csv(data_path)

    # Clean column names (strip spaces)
    df.columns = df.columns.str.strip()

    # Extract exactly 5 features
    features = ['Destination Port', 'Init_Win_bytes_forward', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']
    target = 'Label'

    # Handle NaN and Inf values
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=features + [target])

    # Convert Label to binary: BENIGN = 0, others = 1
    df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

    X = df[features]
    y = df['Label']

    # Scale the data
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    # Calculate balanced class weights
    weights = compute_class_weight(class_weight='balanced', classes=np.unique(y), y=y)
    class_weights_dict = {0: weights[0], 1: weights[1]}
    print(f"Calculated Class Weights: {class_weights_dict}")

    # Build the model: 64-32-16 Dense network with 0.2 Dropout
    # Input shape updated to (5,)
    model = Sequential([
        Dense(64, activation='relu', input_shape=(5,)),
        Dropout(0.2),
        Dense(32, activation='relu'),
        Dense(16, activation='relu'),
        Dense(1, activation='sigmoid')
    ])

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    # Train the model with class weights
    print("Training model...")
    model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.1, verbose=1, class_weight=class_weights_dict)

    # Save the model and scaler to the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model.save(os.path.join(script_dir, "packet_model.keras"))
    joblib.dump(scaler, os.path.join(script_dir, "scaler.pkl"))
    print(f"Model and scaler saved to {script_dir}")

if __name__ == "__main__":
    train_neural_guard()
