# Reversible Image Blur — AES-256-GCM

A Python tool that blurs an image and lets authorized users restore the original using an encryption key.

Built as part of a security research project on Meta AI (Ray-Ban) glasses data privacy.

---

## How It Works

Regular blur is lossy — once applied, you can't undo it. This tool makes blur **reversible** by:

1. Encrypting the original image with AES-256-GCM
2. Applying a strong Gaussian blur and saving that as the "public" version
3. Storing the encrypted original alongside it
4. Letting anyone with the key decrypt and recover the original perfectly

Without the key, all an attacker ever sees is the blurred image.

---

## Files

| File | Purpose |
|------|---------|
| `blur_unblur.py` | Main script — `blur()` and `unblur()` functions + demo |
| `aes256gcm_envelope.py` | AES-256-GCM envelope encryption engine |
| `requirements.txt` | Python dependencies |
| `run.py` | Simple entry point — edit this with your image path |

---

## Setup

**1. Install dependencies**

```bash
pip install -r requirements.txt
```

**2. Add your image**

Copy any `.jpg` or `.png` into this folder.

**3. Edit `run.py`**

Open `run.py` and change `YOUR_IMAGE.jpg` to your actual filename.

**4. Run**

```bash
python run.py
```

---

## Output Files

After running, you'll get:

| File | Description |
|------|-------------|
| `blurred.jpg` | Blurred version — safe to share, no info visible |
| `encrypted.bin` | Encrypted original — useless without the key |
| `unblurred_restored.jpg` | Recovered original — byte-identical to source |

---

## Use as a Library

```python
from blur_unblur import blur, unblur

# Blur and encrypt
key = blur(
    input_path     = "photo.jpg",
    blurred_path   = "photo_blurred.jpg",
    encrypted_path = "photo_encrypted.bin",
    blur_radius    = 25,
)

# Save the key — it's the only way back
print("Key:", key.hex())

# Restore the original (authorized user)
unblur(
    blurred_path   = "photo_blurred.jpg",
    encrypted_path = "photo_encrypted.bin",
    output_path    = "photo_restored.jpg",
    key            = key,
)

# To restore in a later session, load the key from its hex string:
# key = bytes.fromhex("your_hex_key_here")
```

---

## Security Properties

- **AES-256-GCM** — authenticated encryption, 256-bit key
- **Unique IV per encryption** — same image encrypted twice produces different ciphertext
- **GCM authentication tag** — any tampering with the encrypted file is detected and rejected before decryption
- **Wrong key = instant rejection** — `InvalidTag` exception, no partial data returned
- **Byte-perfect recovery** — SHA-256 of restored file matches original exactly
