import os
import json
import base64
import secrets
import hashlib
from pathlib import Path
 
from PIL import Image, ImageFilter
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
 
 
# ─────────────────────────────────────────────────────────────
# CORE FUNCTIONS
# ─────────────────────────────────────────────────────────────
 
def blur(
    input_path: str,
    blurred_path: str,
    encrypted_path: str,
    blur_radius: int = 20,
) -> bytes:
    """
    Blur an image and encrypt the original for later recovery.
 
    Steps:
      1. Read the original image.
      2. Apply a strong Gaussian blur → save as blurred_path.
      3. Encrypt the original bytes with AES-256-GCM.
      4. Save the encrypted bundle to encrypted_path.
      5. Return the 32-byte key (keep this safe — it's the only way back).
 
    Args:
        input_path:     Path to the source image.
        blurred_path:   Where to save the blurred (public) version.
        encrypted_path: Where to save the encrypted original.
        blur_radius:    Gaussian blur radius. Higher = more blurred.
                        20 is strong enough that no details are visible.
 
    Returns:
        key (bytes): 32-byte AES key. Store this securely.
                     Without it the original cannot be recovered.
    """
    print(f"\n[BLUR] Reading  : {input_path}")
    original_image = Image.open(input_path)
    original_bytes = Path(input_path).read_bytes()
    print(f"       Size     : {original_image.size[0]}×{original_image.size[1]} px  |  {len(original_bytes):,} bytes")
 
    # ── Step 1: create the blurred version ───────────────────
    blurred_image = original_image.filter(ImageFilter.GaussianBlur(radius=blur_radius))
    blurred_image.save(blurred_path)
    print(f"[BLUR] Blurred  : saved → {blurred_path}  (radius={blur_radius})")
 
    # ── Step 2: generate a random AES-256 key ─────────────────
    key = secrets.token_bytes(32)   # 256 bits
 
    # ── Step 3: encrypt the original image ───────────────────
    iv         = secrets.token_bytes(12)   # 96-bit IV (NIST recommended)
    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, original_bytes, b"blur-protect")
 
    # ── Step 4: save the encrypted bundle ────────────────────
    bundle = {
        "algorithm":   "AES-256-GCM",
        "iv":          base64.b64encode(iv).decode(),
        "ciphertext":  base64.b64encode(ciphertext).decode(),
        "aad":         "blur-protect",
        "blur_radius": blur_radius,
        "filename":    Path(input_path).name,
        "size_bytes":  len(original_bytes),
    }
    Path(encrypted_path).write_text(json.dumps(bundle, indent=2))
    print(f"[BLUR] Encrypted: saved → {encrypted_path}")
    print(f"[BLUR] Key      : {key.hex()[:16]}...  (first 8 bytes shown)")
    print(f"[BLUR] ✓ Done. Keep the key safe — it's the only way to unblur.\n")
 
    return key
 
 
def unblur(
    blurred_path: str,
    encrypted_path: str,
    output_path: str,
    key: bytes,
) -> Image.Image:
    """
    Restore the original image using the encryption key.
 
    The blurred image is ignored for recovery — only the
    encrypted bundle + key are needed. The blurred path
    is accepted as a parameter for clarity, but not used
    in the decryption process.
 
    Args:
        blurred_path:   Path to the blurred image (not used in decryption,
                        included so callers see the full picture).
        encrypted_path: Path to the encrypted bundle JSON.
        output_path:    Where to write the restored original.
        key:            The 32-byte AES key returned by blur().
 
    Returns:
        The restored PIL Image object.
 
    Raises:
        cryptography.exceptions.InvalidTag  — wrong key or tampered data.
        FileNotFoundError                   — encrypted bundle not found.
    """
    print(f"\n[UNBLUR] Loading encrypted bundle: {encrypted_path}")
    bundle = json.loads(Path(encrypted_path).read_text())
 
    iv         = base64.b64decode(bundle["iv"])
    ciphertext = base64.b64decode(bundle["ciphertext"])
    aad        = bundle["aad"].encode()
 
    # ── Decrypt ───────────────────────────────────────────────
    aesgcm = AESGCM(key)
    original_bytes = aesgcm.decrypt(iv, ciphertext, aad)
    # ^ raises InvalidTag immediately if the key is wrong or data is tampered
 
    # ── Write and return ──────────────────────────────────────
    Path(output_path).write_bytes(original_bytes)
 
    restored = Image.open(output_path)
    print(f"[UNBLUR] ✓ Decrypted successfully")
    print(f"         GCM tag verified — data is intact and untampered")
    print(f"         Restored {len(original_bytes):,} bytes → {output_path}")
    print(f"         Image: {restored.size[0]}×{restored.size[1]} px\n")
 
    return restored
 
 
def unblur_wrong_key_demo(encrypted_path: str):
    """
    Show what happens when someone tries the wrong key.
    Used in the demo to prove that without the key, recovery is impossible.
    """
    print(f"\n[DEMO] Attempting decryption with a WRONG key...")
    wrong_key  = secrets.token_bytes(32)   # random — definitely wrong
    bundle     = json.loads(Path(encrypted_path).read_text())
    iv         = base64.b64decode(bundle["iv"])
    ciphertext = base64.b64decode(bundle["ciphertext"])
 
    try:
        AESGCM(wrong_key).decrypt(iv, ciphertext, b"blur-protect")
        print("[DEMO] ✗ FAIL — should not reach here")
    except Exception as e:
        print(f"[DEMO] ✓ Rejected with: {type(e).__name__}")
        print(f"       The blurred image is all an attacker will ever see.\n")
 
 
# ─────────────────────────────────────────────────────────────
# DEMO
# ─────────────────────────────────────────────────────────────
 
def run_demo():
    # Find the sample image from the earlier pipeline
    candidates = [
        "/home/claude/sample_pii_image.jpg",
        "/home/claude/pipeline_output/02_redacted.jpg",
    ]
    src = next((p for p in candidates if Path(p).exists()), None)
 
    if src is None:
        # Create a simple synthetic image if none found
        print("[DEMO] No sample image found — creating a synthetic one.")
        img = Image.new("RGB", (400, 300), color=(240, 230, 210))
        from PIL import ImageDraw, ImageFont
        draw = ImageDraw.Draw(img)
        draw.text((30, 100), "SSN: 523-88-4471", fill=(20, 20, 80))
        draw.text((30, 140), "Card: 4111 1111 1111 1111", fill=(20, 20, 80))
        draw.text((30, 180), "PIN: 8842", fill=(20, 20, 80))
        src = "/tmp/synthetic_demo.jpg"
        img.save(src)
 
    out      = Path("/mnt/user-data/outputs")
    blurred  = str(out / "blurred.jpg")
    enc      = str(out / "encrypted.bin")
    restored = str(out / "unblurred_restored.jpg")
 
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║             REVERSIBLE BLUR — Demo                          ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"\nSource image: {src}")
 
    # ── 1. Blur + encrypt ─────────────────────────────────────
    key = blur(src, blurred, enc, blur_radius=25)
 
    # ── 2. Verify wrong key is rejected ───────────────────────
    unblur_wrong_key_demo(enc)
 
    # ── 3. Unblur with correct key ─────────────────────────────
    print("[DEMO] Now unblurring with the CORRECT key...")
    unblur(blurred, enc, restored, key)
 
    # ── 4. Confirm byte-level identity ────────────────────────
    original_hash = hashlib.sha256(Path(src).read_bytes()).hexdigest()
    restored_hash = hashlib.sha256(Path(restored).read_bytes()).hexdigest()
    match = original_hash == restored_hash
 
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  RESULT                                                      ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Original SHA-256 : {original_hash[:40]}  ║")
    print(f"║  Restored SHA-256 : {restored_hash[:40]}  ║")
    print(f"║  Byte-identical   : {'✓ YES — perfect recovery' if match else '✗ NO — mismatch'}{'':>26}║")
    print("╚══════════════════════════════════════════════════════════════╝\n")
    print("  Files saved:")
    print(f"    blurred.jpg            → blurred (public) version")
    print(f"    encrypted.bin          → encrypted original (needs key)")
    print(f"    unblurred_restored.jpg → restored original\n")
 
 
if __name__ == "__main__":
    run_demo()
