import os
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

import pandas as pd
import numpy as np
import glob
import pickle
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import classification_report, confusion_matrix
import keras
from keras.models import Sequential
from keras.layers import Dense, Dropout, BatchNormalization, Activation
from keras.callbacks import EarlyStopping, ReduceLROnPlateau

# ═══════════════════════════════════════════════════════════════════════
# FEATURE CONFIGURATION — 12 features, all extractable by sniffer.py
# ═══════════════════════════════════════════════════════════════════════
FEATURES = [
    ' Destination Port',           # 1 - target port
    'Init_Win_bytes_forward',      # 2 - TCP window size of initiator
    ' Flow Duration',              # 3 - microseconds
    ' Total Fwd Packets',          # 4 - forward packet count
    ' Total Backward Packets',     # 5 - backward packet count
    'Total Length of Fwd Packets',  # 6 - total forward payload bytes
    ' Total Length of Bwd Packets', # 7 - total backward payload bytes
    ' Flow Packets/s',             # 8 - packet rate
    ' SYN Flag Count',             # 9 - SYN flags (PortScan signature)
    ' RST Flag Count',             # 10 - RST flags (scan response signature)
    ' Fwd Packet Length Mean',     # 11 - avg fwd packet size
    ' Average Packet Size',        # 12 - overall avg packet size
]

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


def build_model(input_dim, num_classes):
    """
    Improved architecture with BatchNormalization + Dropout for
    better generalization and resistance to class imbalance.
    """
    model = Sequential([
        # Layer 1
        Dense(128, input_shape=(input_dim,)),
        BatchNormalization(),
        Activation('relu'),
        Dropout(0.3),

        # Layer 2
        Dense(64),
        BatchNormalization(),
        Activation('relu'),
        Dropout(0.3),

        # Layer 3
        Dense(32),
        BatchNormalization(),
        Activation('relu'),
        Dropout(0.2),

        # Output
        Dense(num_classes, activation='softmax')
    ])
    return model


def main():
    # ═══════════════════════════════════════════════════════════════════
    # 1. LOAD DATA
    # ═══════════════════════════════════════════════════════════════════
    csv_files = sorted(glob.glob('raw_data/*.csv'))
    df_list = []

    print(f"[1/6] Loading {len(csv_files)} CSV files...")
    for f in csv_files:
        print(f"  → {f}")
        df = pd.read_csv(f, usecols=FEATURES + [LABEL_COL])
        df_list.append(df)

    df = pd.concat(df_list, ignore_index=True)
    print(f"  Total rows loaded: {len(df):,}")

    # ═══════════════════════════════════════════════════════════════════
    # 2. MAP LABELS
    # ═══════════════════════════════════════════════════════════════════
    print("[2/6] Mapping labels...")
    df[LABEL_COL] = df[LABEL_COL].apply(map_label)

    label_counts = df[LABEL_COL].value_counts().sort_index()
    for idx, count in label_counts.items():
        print(f"  Class {idx} ({CLASS_NAMES[idx]}): {count:,}")

    # ═══════════════════════════════════════════════════════════════════
    # 3. CLEAN DATA
    # ═══════════════════════════════════════════════════════════════════
    print("[3/6] Cleaning data...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    rows_before = len(df)
    df.dropna(inplace=True)
    rows_after = len(df)
    if rows_before != rows_after:
        print(f"  Dropped {rows_before - rows_after:,} rows with NaN/Inf values")
    print(f"  Clean rows: {rows_after:,}")

    X = df[FEATURES].values
    y = df[LABEL_COL].values

    # ═══════════════════════════════════════════════════════════════════
    # 4. TRAIN/TEST SPLIT (STRATIFIED)
    # ═══════════════════════════════════════════════════════════════════
    print("[4/6] Splitting data (stratified 80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train):,} | Test: {len(X_test):,}")

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # ═══════════════════════════════════════════════════════════════════
    # 5. COMPUTE CLASS WEIGHTS
    # ═══════════════════════════════════════════════════════════════════
    print("[5/6] Computing class weights...")
    unique_classes = np.unique(y_train)
    weights = compute_class_weight('balanced', classes=unique_classes, y=y_train)
    weights = np.clip(weights, 0.5, 5.0)
    class_weight_dict = dict(zip(unique_classes, weights))

    for cls, w in class_weight_dict.items():
        print(f"  Class {cls} ({CLASS_NAMES[cls]}): weight = {w:.4f}")

    # ═══════════════════════════════════════════════════════════════════
    # 6. BUILD & TRAIN MODEL
    # ═══════════════════════════════════════════════════════════════════
    print("[6/6] Building and training model...")
    num_classes = len(unique_classes)
    model = build_model(input_dim=len(FEATURES), num_classes=num_classes)

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )

    model.summary()

    callbacks = [
        EarlyStopping(
            monitor='val_loss',
            patience=5,
            restore_best_weights=True,
            verbose=1
        ),
        ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=3,
            min_lr=1e-6,
            verbose=1
        )
    ]

    history = model.fit(
        X_train_scaled, y_train,
        epochs=30,
        batch_size=512,
        validation_split=0.1,
        class_weight=class_weight_dict,
        callbacks=callbacks,
        verbose=1
    )

    # ═══════════════════════════════════════════════════════════════════
    # EVALUATION
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print("POST-TRAINING EVALUATION")
    print("=" * 70)

    y_pred_probs = model.predict(X_test_scaled, verbose=0, batch_size=2048)
    y_pred = np.argmax(y_pred_probs, axis=1)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=CLASS_NAMES, digits=4, zero_division=0))

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    header = "Predicted →  " + "  ".join(f"{n[:8]:>8}" for n in CLASS_NAMES)
    print(header)
    for i, row in enumerate(cm):
        label = f"{CLASS_NAMES[i][:8]:<8}"
        vals = "  ".join(f"{v:>8}" for v in row)
        print(f"  {label}   {vals}")

    # Key metrics check
    print("\n" + "-" * 70)
    print("TARGET METRICS CHECK:")
    ddos_recall = cm[1][1] / cm[1].sum() if cm[1].sum() > 0 else 0
    portscan_recall = cm[2][2] / cm[2].sum() if cm[2].sum() > 0 else 0
    overall_acc = np.trace(cm) / cm.sum()

    status_ddos = "✅" if ddos_recall >= 0.80 else "❌"
    status_ps = "✅" if portscan_recall >= 0.80 else "❌"
    status_acc = "✅" if overall_acc >= 0.85 else "❌"

    print(f"  {status_ddos} DoS/DDoS Recall:  {ddos_recall:.4f}  (target ≥ 0.80)")
    print(f"  {status_ps} PortScan Recall:  {portscan_recall:.4f}  (target ≥ 0.80)")
    print(f"  {status_acc} Overall Accuracy: {overall_acc:.4f}  (target ≥ 0.85)")
    print("-" * 70)

    # ═══════════════════════════════════════════════════════════════════
    # SAVE MODEL & SCALER
    # ═══════════════════════════════════════════════════════════════════
    os.makedirs('brain', exist_ok=True)

    model.save('brain/neuralguard_v2.h5')
    with open('brain/scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)

    print(f"\n✅ Model saved to brain/neuralguard_v2.h5")
    print(f"✅ Scaler saved to brain/scaler.pkl")
    print(f"✅ Feature count: {len(FEATURES)}")
    print(f"✅ Training complete.")


if __name__ == "__main__":
    main()
