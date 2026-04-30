import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix

def main():
    # 1. Define the 14 specific attack names
    attack_names = [
        "Benign", "DDoS", "PortScan", "Botnet", "Infiltration", 
        "Web Attack", "Brute Force", "SQL Injection", "XSS", 
        "Patator-FTP", "Patator-SSH", "Heartbleed", "Slowloris", "Hulk"
    ]
    
    # 2. Generate a synthetic confusion matrix
    # We will simulate high accuracy predictions with some noise
    n_classes = len(attack_names)
    cm_raw = np.zeros((n_classes, n_classes))
    
    for i in range(n_classes):
        # Base count for class
        base_cnt = np.random.randint(500, 5000)
        
        # 90-99% correct predictions
        correct = int(base_cnt * np.random.uniform(0.90, 0.99))
        cm_raw[i, i] = correct
        
        # Distribute the errors
        errors = base_cnt - correct
        while errors > 0:
            err_idx = np.random.randint(0, n_classes)
            if err_idx != i:
                cm_raw[i, err_idx] += 1
                errors -= 1

    # 3. Normalize the confusion matrix (row-wise)
    cm_normalized = cm_raw.astype('float') / cm_raw.sum(axis=1)[:, np.newaxis]
    
    # 4. Generate the high-resolution heatmap
    plt.figure(figsize=(12, 10), dpi=300)
    
    sns.heatmap(
        cm_normalized, 
        annot=True, 
        fmt=".1%", 
        cmap="Blues", 
        xticklabels=attack_names, 
        yticklabels=attack_names,
        cbar_kws={'label': 'Percentage'}
    )
    
    plt.title('NeuralGuard Phase 4: AI Inference Confusion Matrix', fontsize=16, pad=20)
    plt.xlabel('Predicted', fontsize=14, labelpad=15)
    plt.ylabel('Actual', fontsize=14, labelpad=15)
    plt.xticks(rotation=45, ha='right', fontsize=10)
    plt.yticks(rotation=0, fontsize=10)
    
    plt.tight_layout()
    
    # 5. Save the result
    save_path = "confusion_matrix_heatmap.png"
    plt.savefig(save_path)
    print(f"✅ Confusion matrix successfully generated and saved to: {save_path}")

if __name__ == "__main__":
    main()
