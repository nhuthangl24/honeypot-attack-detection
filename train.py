import os
import gzip
import json
import math
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score, confusion_matrix

def calculate_entropy(text: str) -> float:
    if not text or not isinstance(text, str):
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return float(-sum([p * math.log(p, 2) for p in prob]))

def parse_iso_time(ts_str):
    if not ts_str:
        return None
    try:
        clean_ts = str(ts_str).replace("Z", "")
        return datetime.fromisoformat(clean_ts)
    except Exception:
        return None

def extract_cyberlab_features(raw_path: str) -> pd.DataFrame:
    print(f"[*] Extracting features from real CyberLab dataset: {raw_path}")
    with gzip.open(raw_path, "rt", encoding="utf-8") as f:
        data = json.load(f)

    session_rows = []
    
    for session_obj in data:
        for session_id, events in session_obj.items():
            if not events:
                continue

            src_ip = None
            start_time = None
            end_time = None
            
            login_attempts = 0
            login_success = 0
            login_failed = 0
            usernames = []
            passwords = []
            
            commands = []
            command_timestamps = []
            file_downloads = 0
            direct_tcpip = 0
            
            for ev in events:
                eid = ev.get("eventid", "")
                ts = parse_iso_time(ev.get("timestamp"))
                
                if ts:
                    if start_time is None or ts < start_time:
                        start_time = ts
                    if end_time is None or ts > end_time:
                        end_time = ts
                
                if not src_ip and ev.get("src_ip_identifier"):
                    src_ip = ev.get("src_ip_identifier")
                
                # Login events
                if eid == "cowrie.login.success":
                    login_attempts += 1
                    login_success += 1
                    if ev.get("username"): usernames.append(ev.get("username"))
                    if ev.get("password"): passwords.append(ev.get("password"))
                elif eid == "cowrie.login.failed":
                    login_attempts += 1
                    login_failed += 1
                    if ev.get("username"): usernames.append(ev.get("username"))
                    if ev.get("password"): passwords.append(ev.get("password"))
                    
                # Command events
                if "command" in eid:
                    inp = ev.get("input")
                    msg = ev.get("message", "")
                    cmd = None
                    if inp:
                        cmd = inp
                    elif msg.startswith("Command found:"):
                        cmd = msg.replace("Command found:", "").strip()
                    elif msg.startswith("Command not found:"):
                        cmd = msg.replace("Command not found:", "").strip()
                    if cmd:
                        commands.append(cmd)
                        if ts: command_timestamps.append(ts)
                
                # File download & Direct TCP-IP
                if eid == "cowrie.session.file_download":
                    file_downloads += 1
                elif "direct-tcpip" in eid:
                    direct_tcpip += 1

            duration_sec = 0.0
            if start_time and end_time:
                duration_sec = max(0.0, float((end_time - start_time).total_seconds()))
                
            unique_u = len(set(usernames)) if usernames else (1 if login_attempts > 0 else 0)
            unique_p = len(set(passwords)) if passwords else (1 if login_attempts > 0 else 0)
            u_entropy = calculate_entropy("".join(usernames))
            p_entropy = calculate_entropy("".join(passwords))
            is_root = 1.0 if "root" in [u.lower() for u in usernames] else 0.0
            
            total_cmds = len(commands)
            unique_cmd_ratio = float(len(set(commands)) / total_cmds) if total_cmds > 0 else 0.0
            
            # Inter-command delays
            inter_delays = []
            if len(command_timestamps) > 1:
                command_timestamps.sort()
                for i in range(len(command_timestamps) - 1):
                    diff = (command_timestamps[i+1] - command_timestamps[i]).total_seconds()
                    inter_delays.append(diff)
            
            avg_delay = float(np.mean(inter_delays)) if inter_delays else 0.0
            std_delay = float(np.std(inter_delays)) if inter_delays else 0.0
            failed_ratio = float(login_failed / login_attempts) if login_attempts > 0 else 0.0

            # Phân loại nhãn chuẩn an ninh mạng (Ground Truth Heuristic)
            cmd_text_joined = " ".join(commands).lower()
            has_dropper_indicator = (file_downloads > 0 or 
                                    any(kw in cmd_text_joined for kw in ["wget", "curl", "tftp", "njs.sh", "bins.sh", "chmod +x", "chmod 777", ".sh"]))
            
            if login_attempts == 0 and total_cmds == 0:
                label = "Reconnaissance_Probe"
            elif login_attempts > 0 and login_success == 0 and total_cmds == 0:
                label = "Brute_Force_Bot"
            elif login_success > 0 and has_dropper_indicator:
                label = "Automated_Malware_Dropper"
            elif login_success > 0 and (total_cmds > 0 or duration_sec > 5.0):
                label = "Interactive_Attacker"
            else:
                label = "Reconnaissance_Probe"

            session_rows.append({
                "session_id": session_id,
                "src_ip_identifier": src_ip or "unknown",
                "total_events": len(events),
                "duration_seconds": duration_sec,
                "login_attempts_count": login_attempts,
                "failed_login_count": login_failed,
                "failed_login_ratio": failed_ratio,
                "success_login_count": login_success,
                "unique_usernames_count": unique_u,
                "unique_passwords_count": unique_p,
                "username_entropy": u_entropy,
                "password_entropy": p_entropy,
                "is_root_targeted": is_root,
                "total_commands_count": total_cmds,
                "unique_commands_ratio": unique_cmd_ratio,
                "avg_inter_command_delay": avg_delay,
                "std_inter_command_delay": std_delay,
                "file_download_count": file_downloads,
                "direct_tcpip_count": direct_tcpip,
                "label": label
            })

    df = pd.DataFrame(session_rows)
    print(f"[+] Successfully extracted {len(df):,} sessions from CyberLab dataset.")
    return df

def main():
    print("=" * 70)
    print("   TRAINING XGBOOST CLASSIFIER ON REAL HONEYPOT DATASET (ZENODO 3687527)")
    print("=" * 70)

    raw_path = "data/raw/cyberlab_2019-05-13.json.gz"
    if not os.path.isfile(raw_path):
        print(f"[*] Dataset not found at {raw_path}. Downloading from Zenodo...")
        os.makedirs("data/raw", exist_ok=True)
        import subprocess
        subprocess.run([
            "curl", "-L",
            "https://zenodo.org/records/3687527/files/cyberlab_2019-05-13.json.gz?download=1",
            "-o", raw_path
        ], check=True)

    os.makedirs("data/processed", exist_ok=True)
    df = extract_cyberlab_features(raw_path)
    
    # Save processed dataset
    df.to_csv("data/processed/sessions.csv", index=False)
    try:
        df.to_parquet("data/processed/sessions.parquet", index=False)
    except Exception:
        pass

    print("\n[+] Class distribution in real dataset:")
    print("-" * 50)
    for lbl, count in df["label"].value_counts().items():
        print(f"  {lbl:<30} : {count:>6,} ({count/len(df):.1%})")
    print("-" * 50)

    feature_cols = [
        "total_events", "duration_seconds", "login_attempts_count",
        "failed_login_count", "failed_login_ratio", "success_login_count",
        "unique_usernames_count", "unique_passwords_count",
        "username_entropy", "password_entropy", "is_root_targeted",
        "total_commands_count", "unique_commands_ratio",
        "avg_inter_command_delay", "std_inter_command_delay",
        "file_download_count", "direct_tcpip_count"
    ]

    X = df[feature_cols].copy()
    y_raw = df["label"].copy()

    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    class_names = list(le.classes_)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\n[+] Train set: {len(X_train):,} samples")
    print(f"[+] Test set:  {len(X_test):,} samples")

    scaler = StandardScaler()
    scaler.fit(X_train)

    from sklearn.utils.class_weight import compute_sample_weight
    sample_weights = compute_sample_weight('balanced', y_train)

    print("\n[*] Training Balanced XGBoost Classifier...")
    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        eval_metric="mlogloss",
        n_jobs=-1
    )
    model.fit(X_train, y_train, sample_weight=sample_weights)

    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds, average="macro")

    print(f"\n[+] XGBOOST TRAINING RESULTS:")
    print(f"    - Accuracy: {acc * 100:.2f}%")
    print(f"    - Macro-F1: {f1 * 100:.2f}%")
    print("\n[+] Classification Report:")
    print(classification_report(y_test, preds, target_names=class_names, digits=4))

    # Save artifacts
    os.makedirs("artifacts", exist_ok=True)
    import joblib
    joblib.dump(model, "artifacts/session_model.joblib")
    joblib.dump(le, "artifacts/session_label_encoder.joblib")
    joblib.dump(scaler, "artifacts/session_scaler.joblib")

    cm = confusion_matrix(y_test, preds).tolist()
    meta = {
        "champion_model": "XGBoost Classifier",
        "dataset_source": "CyberLab Cowrie Honeypot (Zenodo 3687527)",
        "total_dataset_samples": len(df),
        "feature_columns": feature_cols,
        "class_names": class_names,
        "results_comparison": {
            "XGBoost Classifier": {
                "accuracy": float(acc),
                "macro_f1": float(f1)
            }
        },
        "confusion_matrix": cm,
        "trained_at": datetime.utcnow().isoformat() + "Z"
    }

    with open("artifacts/session_metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"[+] Saved model artifacts to artifacts/ directory!")
    print(f"[+] Ready for serving on SOC Dashboard!")

if __name__ == "__main__":
    main()
