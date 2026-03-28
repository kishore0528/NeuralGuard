import os
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

import pandas as pd
import numpy as np
import glob
import pickle
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from keras.models import load_model

# Must match train_v2.py exactly
FEATURES = [' Destination Port', 'Init_Win_bytes_forward', ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets']
LABEL_COL = ' Label'

CLASS_NAMES = ['BENIGN', 'DoS/DDoS', 'PortScan', 'Patator', 'Other']

def map_label(label):
    label = str(label).strip().upper()
    if label == 'BENIGN':
        return 0
    elif 'DOS' in label or 'DDOS' in label:
        return 1
    elif 'PORTSCAN' in label:
        return 2
    elif 'PATATOR' in label or 'BRUTE FORCE' in label:
        return 3
    else:
        return 4

def main():
    # 1. Load data (same pipeline as training)
    csv_files = glob.glob('../raw_data/*.csv')
    df_list = []
    print(f"Loading {len(csv_files)} files...")
    for f in sorted(csv_files):
        print(f"  Reading {f}...")
        df = pd.read_csv(f, usecols=FEATURES + [LABEL_COL])
        df_list.append(df)

    df = pd.concat(df_list, ignore_index=True)
    print(f"Total rows: {len(df)}")

    # 2. Map labels
    df[LABEL_COL] = df[LABEL_COL].apply(map_label)

    # 3. Clean
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    print(f"Clean rows: {len(df)}")

    X = df[FEATURES]
    y = df[LABEL_COL]

    # 4. Same split as training (random_state=42, test_size=0.2)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 5. Re-fit scaler on train set (to match what training did)
    scaler = StandardScaler()
    scaler.fit(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 6. Load existing model
    print("\nLoading existing model from neuralguard_v2.h5...")
    model = load_model('neuralguard_v2.h5')

    # 7. Predict
    print("Running predictions on test set...")
    y_pred_probs = model.predict(X_test_scaled, verbose=0, batch_size=2048)
    y_pred = np.argmax(y_pred_probs, axis=1)

    # 8. Report
    print("\n" + "=" * 70)
    print("BASELINE EVALUATION RESULTS")
    print("=" * 70)
    print(f"\nTest set size: {len(y_test)}")

    print("\nClass distribution in test set:")
    for i, name in enumerate(CLASS_NAMES):
        count = (y_test == i).sum()
        print(f"  {i} ({name}): {count}")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=CLASS_NAMES, digits=4, zero_division=0))

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    # Header
    header = "Predicted →  " + "  ".join(f"{n[:8]:>8}" for n in CLASS_NAMES)
    print(header)
    for i, row in enumerate(cm):
        label = f"{CLASS_NAMES[i][:8]:<8}"
        vals = "  ".join(f"{v:>8}" for v in row)
        print(f"  {label}   {vals}")

    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()
