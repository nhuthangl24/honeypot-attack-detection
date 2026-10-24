import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score

def generate_synthetic_honeypot_dataset(n_samples=4000, random_state=42):
    np.random.seed(random_state)
    
    classes = [
        "Reconnaissance_Probe",
        "Brute_Force_Bot",
        "Interactive_Attacker",
        "Automated_Malware_Dropper"
    ]
    
    samples_per_class = n_samples // 4
    rows = []
    
    # 1. Reconnaissance_Probe (Quét cổng, thăm dò kết nối đơn giản)
    for _ in range(samples_per_class):
        tot_events = np.random.randint(1, 4)
        duration = float(np.random.uniform(0.1, 3.5))
        login_attempts = np.random.choice([0, 1], p=[0.7, 0.3])
        failed_logins = login_attempts
        success_logins = 0
        u_count = 1 if login_attempts > 0 else 0
        p_count = 1 if login_attempts > 0 else 0
        u_ent = float(np.random.uniform(0.0, 2.0)) if u_count > 0 else 0.0
        p_ent = float(np.random.uniform(0.0, 2.5)) if p_count > 0 else 0.0
        is_root = np.random.choice([0, 1], p=[0.8, 0.2]) if u_count > 0 else 0
        tot_cmds = 0
        uniq_cmd_ratio = 0.0
        avg_delay = 0.0
        std_delay = 0.0
        downloads = 0
        direct_tcpip = 0
        
        rows.append({
            "total_events": tot_events,
            "duration_seconds": duration,
            "login_attempts_count": login_attempts,
            "failed_login_count": failed_logins,
            "failed_login_ratio": 1.0 if login_attempts > 0 else 0.0,
            "success_login_count": success_logins,
            "unique_usernames_count": u_count,
            "unique_passwords_count": p_count,
            "username_entropy": u_ent,
            "password_entropy": p_ent,
            "is_root_targeted": is_root,
            "total_commands_count": tot_cmds,
            "unique_commands_ratio": uniq_cmd_ratio,
            "avg_inter_command_delay": avg_delay,
            "std_inter_command_delay": std_delay,
            "file_download_count": downloads,
            "direct_tcpip_count": direct_tcpip,
            "label": "Reconnaissance_Probe"
        })
        
    # 2. Brute_Force_Bot (Dò quét mật khẩu: nhiều lần pass sai, không gõ lệnh)
    for _ in range(samples_per_class):
        failed_logins = np.random.randint(3, 40)
        login_attempts = failed_logins
        success_logins = 0
        tot_events = failed_logins * 2 + np.random.randint(0, 5)
        duration = float(np.random.uniform(2.0, 45.0))
        u_count = np.random.randint(1, min(failed_logins, 10))
        p_count = np.random.randint(2, failed_logins + 1)
        u_ent = float(np.random.uniform(1.2, 4.0))
        p_ent = float(np.random.uniform(2.0, 4.8))
        is_root = np.random.choice([0, 1], p=[0.3, 0.7])
        tot_cmds = 0
        uniq_cmd_ratio = 0.0
        avg_delay = 0.0
        std_delay = 0.0
        downloads = 0
        direct_tcpip = 0
        
        rows.append({
            "total_events": tot_events,
            "duration_seconds": duration,
            "login_attempts_count": login_attempts,
            "failed_login_count": failed_logins,
            "failed_login_ratio": 1.0,
            "success_login_count": success_logins,
            "unique_usernames_count": u_count,
            "unique_passwords_count": p_count,
            "username_entropy": u_ent,
            "password_entropy": p_ent,
            "is_root_targeted": is_root,
            "total_commands_count": tot_cmds,
            "unique_commands_ratio": uniq_cmd_ratio,
            "avg_inter_command_delay": avg_delay,
            "std_inter_command_delay": std_delay,
            "file_download_count": downloads,
            "direct_tcpip_count": direct_tcpip,
            "label": "Brute_Force_Bot"
        })
        
    # 3. Interactive_Attacker (Gõ lệnh khám phá: whoami, ip a, uname -a, ls, pwd - KHÔNG download malware)
    for _ in range(samples_per_class):
        failed_logins = np.random.choice([0, 1, 2], p=[0.7, 0.2, 0.1])
        success_logins = 1
        login_attempts = failed_logins + success_logins
        tot_cmds = np.random.randint(1, 15)
        tot_events = login_attempts * 2 + tot_cmds * 2 + np.random.randint(1, 4)
        avg_delay = float(np.random.uniform(2.5, 25.0)) # Người gõ tay với độ trễ tự nhiên
        std_delay = float(np.random.uniform(1.2, 10.0))
        duration = float(tot_cmds * avg_delay + np.random.uniform(5.0, 30.0))
        u_count = 1
        p_count = login_attempts
        u_ent = float(np.random.uniform(1.0, 3.0))
        p_ent = float(np.random.uniform(1.0, 3.5))
        is_root = np.random.choice([0, 1], p=[0.4, 0.6])
        uniq_cmd_ratio = float(np.random.uniform(0.7, 1.0))
        downloads = 0 # KHÔNG TẢI MÃ ĐỘC
        direct_tcpip = 0
        
        rows.append({
            "total_events": tot_events,
            "duration_seconds": duration,
            "login_attempts_count": login_attempts,
            "failed_login_count": failed_logins,
            "failed_login_ratio": float(failed_logins / login_attempts),
            "success_login_count": success_logins,
            "unique_usernames_count": u_count,
            "unique_passwords_count": p_count,
            "username_entropy": u_ent,
            "password_entropy": p_ent,
            "is_root_targeted": is_root,
            "total_commands_count": tot_cmds,
            "unique_commands_ratio": uniq_cmd_ratio,
            "avg_inter_command_delay": avg_delay,
            "std_inter_command_delay": std_delay,
            "file_download_count": downloads,
            "direct_tcpip_count": direct_tcpip,
            "label": "Interactive_Attacker"
        })
        
    # 4. Automated_Malware_Dropper (Tải mã độc wget/curl, script bot.sh, tốc độ máy bot gõ cực nhanh)
    for _ in range(samples_per_class):
        failed_logins = np.random.choice([0, 1], p=[0.8, 0.2])
        success_logins = 1
        login_attempts = failed_logins + success_logins
        downloads = np.random.randint(1, 5) # CÓ LỆNH DOWNLOAD
        tot_cmds = downloads + np.random.randint(1, 6)
        avg_delay = float(np.random.uniform(0.1, 1.8)) # Bot gõ siêu nhanh (<2s)
        std_delay = float(np.random.uniform(0.05, 0.9))
        duration = float(tot_cmds * avg_delay + np.random.uniform(1.0, 8.0))
        tot_events = login_attempts * 2 + tot_cmds * 2 + np.random.randint(1, 3)
        u_count = 1
        p_count = login_attempts
        u_ent = float(np.random.uniform(1.0, 3.0))
        p_ent = float(np.random.uniform(1.0, 3.5))
        is_root = np.random.choice([0, 1], p=[0.2, 0.8])
        uniq_cmd_ratio = float(np.random.uniform(0.8, 1.0))
        direct_tcpip = np.random.choice([0, 1], p=[0.8, 0.2])
        
        rows.append({
            "total_events": tot_events,
            "duration_seconds": duration,
            "login_attempts_count": login_attempts,
            "failed_login_count": failed_logins,
            "failed_login_ratio": float(failed_logins / login_attempts),
            "success_login_count": success_logins,
            "unique_usernames_count": u_count,
            "unique_passwords_count": p_count,
            "username_entropy": u_ent,
            "password_entropy": p_ent,
            "is_root_targeted": is_root,
            "total_commands_count": tot_cmds,
            "unique_commands_ratio": uniq_cmd_ratio,
            "avg_inter_command_delay": avg_delay,
            "std_inter_command_delay": std_delay,
            "file_download_count": downloads,
            "direct_tcpip_count": direct_tcpip,
            "label": "Automated_Malware_Dropper"
        })
        
    df = pd.DataFrame(rows)
    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    return df

def main():
    print("[*] Generating comprehensive Honeypot detection dataset...")
    df = generate_synthetic_honeypot_dataset(n_samples=8000)
    print(f"[+] Total samples: {len(df):,}")
    print(df["label"].value_counts())
    
    feature_cols = [
        "total_events",
        "duration_seconds",
        "login_attempts_count",
        "failed_login_count",
        "failed_login_ratio",
        "success_login_count",
        "unique_usernames_count",
        "unique_passwords_count",
        "username_entropy",
        "password_entropy",
        "is_root_targeted",
        "total_commands_count",
        "unique_commands_ratio",
        "avg_inter_command_delay",
        "std_inter_command_delay",
        "file_download_count",
        "direct_tcpip_count"
    ]
    
    X = df[feature_cols].copy()
    y_raw = df["label"].copy()
    
    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    class_names = list(le.classes_)
    print(f"[+] Encoded classes: {class_names}")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"[*] Training XGBoost Classifier...")
    xgb = XGBClassifier(
        n_estimators=150,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        eval_metric="mlogloss",
        n_jobs=-1
    )
    xgb.fit(X_train, y_train)
    
    preds = xgb.predict(X_test)
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds, average="macro")
    print(f"\n[+] XGBoost Accuracy: {acc:.4f} | Macro F1: {f1:.4f}")
    print("\n[+] Detailed Classification Report:")
    print(classification_report(y_test, preds, target_names=class_names))
    
    os.makedirs("artifacts", exist_ok=True)
    joblib.dump(xgb, "artifacts/session_model.joblib")
    joblib.dump(le, "artifacts/session_label_encoder.joblib")
    
    scaler = StandardScaler()
    scaler.fit(X_train)
    joblib.dump(scaler, "artifacts/session_scaler.joblib")
    
    meta = {
        "champion_model": "XGBoost Classifier",
        "feature_columns": feature_cols,
        "class_names": class_names,
        "results_comparison": {
            "XGBoost Classifier": {
                "accuracy": float(acc),
                "macro_f1": float(f1)
            }
        }
    }
    with open("artifacts/session_metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
        
    print("[+] Successfully saved XGBoost artifacts to artifacts/session_model.joblib")

if __name__ == "__main__":
    main()
