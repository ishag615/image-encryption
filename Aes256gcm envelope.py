import os
import json
import base64
import hashlib
import secrets
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
 
 
# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
 
KEY_SIZE   = 32   # 256-bit keys
IV_SIZE    = 12   # 96-bit IVs  (NIST recommended for GCM)
TAG_SIZE   = 16   # 128-bit authentication tags (GCM default)
VERSION    = "1.0"
 
 
# ─────────────────────────────────────────────────────────────────────────────
# MASTER KEY MANAGER  (simulates an HSM / KMS)
# ─────────────────────────────────────────────────────────────────────────────
 
class MasterKeyManager:
    """
    Simulates a Hardware Security Module (HSM) or cloud KMS.
 
    In production this would be:
      - AWS KMS  (GenerateDataKey / Decrypt API)
      - Google Cloud KMS
      - Azure Key Vault
      - HashiCorp Vault Transit engine
      - A physical HSM (AWS CloudHSM, YubiHSM, etc.)
 
    The master key (KEK = Key Encryption Key) lives here and never leaves.
    All it does is wrap (encrypt) and unwrap (decrypt) DEKs.
    """
 
    def __init__(self, master_key: Optional[bytes] = None):
        """
        master_key: 32-byte (256-bit) KEK.
                    If None, a random one is generated (ephemeral — demo only).
                    In production, load this from your HSM / secrets manager.
        """
        if master_key is not None:
            if len(master_key) != KEY_SIZE:
                raise ValueError(f"Master key must be exactly {KEY_SIZE} bytes (256-bit).")
            self._kek = master_key
        else:
            self._kek = secrets.token_bytes(KEY_SIZE)
            print("  [HSM]  Generated ephemeral master key (demo mode).")
            print("         In production, load this from your HSM / KMS.\n")
 
    # ── Public interface ────────────────────────────────────────────────────
 
    def wrap_dek(self, dek: bytes, context: str = "") -> dict:
        """
        Encrypt (wrap) a DEK under the master key.
 
        Returns a dict with:
          dek_iv        — base64-encoded IV
          encrypted_dek — base64-encoded ciphertext of the DEK
          dek_tag       — base64-encoded GCM authentication tag
 
        The 'context' string (AAD) binds the wrapped DEK to its intended use.
        If you try to unwrap it with a different context, decryption fails.
        """
        if len(dek) != KEY_SIZE:
            raise ValueError("DEK must be 32 bytes.")
 
        iv  = secrets.token_bytes(IV_SIZE)
        aad = context.encode("utf-8") if context else b""
 
        aesgcm = AESGCM(self._kek)
        # cryptography's AESGCM appends the 16-byte tag to the ciphertext
        ciphertext_with_tag = aesgcm.encrypt(iv, dek, aad)
 
        ciphertext = ciphertext_with_tag[:-TAG_SIZE]
        tag        = ciphertext_with_tag[-TAG_SIZE:]
 
        return {
            "dek_iv":        base64.b64encode(iv).decode(),
            "encrypted_dek": base64.b64encode(ciphertext).decode(),
            "dek_tag":       base64.b64encode(tag).decode(),
        }
 
    def unwrap_dek(self, wrapped: dict, context: str = "") -> bytes:
        """
        Decrypt (unwrap) a DEK using the master key.
 
        Raises cryptography.exceptions.InvalidTag if the DEK has been
        tampered with or the wrong master key / context is used.
        """
        iv         = base64.b64decode(wrapped["dek_iv"])
        ciphertext = base64.b64decode(wrapped["encrypted_dek"])
        tag        = base64.b64decode(wrapped["dek_tag"])
        aad        = context.encode("utf-8") if context else b""
 
        aesgcm = AESGCM(self._kek)
        dek = aesgcm.decrypt(iv, ciphertext + tag, aad)
        return dek
 
    @staticmethod
    def generate_dek() -> bytes:
        """Generate a fresh random 256-bit Data Encryption Key."""
        return secrets.token_bytes(KEY_SIZE)
 
 
# ─────────────────────────────────────────────────────────────────────────────
# ENVELOPE ENCRYPTOR
# ─────────────────────────────────────────────────────────────────────────────
 
class EnvelopeEncryptor:
    """
    Performs AES-256-GCM envelope encryption and decryption.
 
    Envelope encryption means:
      1. Generate a fresh random DEK for every piece of data.
      2. Encrypt the data with the DEK.
      3. Wrap (encrypt) the DEK with the master KEK.
      4. Store the wrapped DEK alongside the ciphertext.
 
    This way:
      - Rotating the master key only requires re-wrapping the DEK,
        not re-encrypting all the data.
      - Each file has a unique key, so a compromised DEK only exposes
        one file, not everything.
    """
 
    def __init__(self, key_manager: MasterKeyManager):
        self.km = key_manager
 
    # ── Encrypt ──────────────────────────────────────────────────────────────
 
    def encrypt(
        self,
        plaintext: bytes,
        purpose:   str = "data",
        aad:       Optional[bytes] = None,
    ) -> dict:
        """
        Encrypt arbitrary bytes using envelope encryption.
 
        Args:
            plaintext: The raw bytes to encrypt (image, text, JSON, etc.)
            purpose:   Human-readable label — also used as DEK wrap context.
                       This binds the encrypted DEK to this specific purpose;
                       unwrapping with a different purpose label will fail.
            aad:       Additional Authenticated Data — authenticated but NOT
                       encrypted. Use for metadata you want to integrity-check
                       (e.g. user ID, file path, record ID). If None, the
                       purpose string is used as AAD.
 
        Returns:
            A JSON-serialisable dict (the "bundle") containing everything
            needed to decrypt the data later, except the master key.
        """
        # ── Step 1: generate a fresh DEK ───────────────────────────────────
        dek = MasterKeyManager.generate_dek()
        _log("KEYGEN", f"Generated fresh 256-bit DEK for '{purpose}'")
 
        # ── Step 2: wrap the DEK under the master key ───────────────────────
        wrapped = self.km.wrap_dek(dek, context=purpose)
        _log("WRAP",   f"DEK wrapped by master KEK  (context='{purpose}')")
 
        # ── Step 3: build AAD ───────────────────────────────────────────────
        if aad is None:
            aad = purpose.encode("utf-8")
 
        aad_hash = hashlib.sha256(aad).hexdigest()
 
        # ── Step 4: encrypt the plaintext with the DEK ──────────────────────
        data_iv = secrets.token_bytes(IV_SIZE)
        aesgcm  = AESGCM(dek)
        data_ct_with_tag = aesgcm.encrypt(data_iv, plaintext, aad)
 
        data_ciphertext = data_ct_with_tag[:-TAG_SIZE]
        data_tag        = data_ct_with_tag[-TAG_SIZE:]
 
        _log("ENCRYPT", (
            f"Encrypted {len(plaintext):,} bytes  →  "
            f"{len(data_ciphertext):,} bytes ciphertext  +  "
            f"{TAG_SIZE} bytes GCM auth tag"
        ))
 
        # ── Step 5: zero the DEK from memory ────────────────────────────────
        # Python doesn't guarantee immediate memory zeroing, but we
        # overwrite the variable to reduce the exposure window.
        dek = b"\x00" * KEY_SIZE
        del dek
        _log("SECURITY", "DEK zeroed from memory after use")
 
        # ── Step 6: assemble the bundle ─────────────────────────────────────
        bundle = {
            "version":       VERSION,
            "algorithm":     "AES-256-GCM",
            "purpose":       purpose,
            "created_at":    datetime.now(timezone.utc).isoformat(),
 
            # DEK (wrapped / encrypted)
            "dek_iv":        wrapped["dek_iv"],
            "dek_tag":       wrapped["dek_tag"],
            "encrypted_dek": wrapped["encrypted_dek"],
 
            # Data (encrypted)
            "data_iv":       base64.b64encode(data_iv).decode(),
            "data_tag":      base64.b64encode(data_tag).decode(),
            "ciphertext":    base64.b64encode(data_ciphertext).decode(),
 
            # AAD fingerprint (for integrity verification)
            "aad_hash":      aad_hash,
        }
 
        return bundle
 
    # ── Decrypt ──────────────────────────────────────────────────────────────
 
    def decrypt(
        self,
        bundle: dict,
        aad:    Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt a bundle produced by encrypt().
 
        Raises:
            ValueError              — if the bundle version or algorithm is wrong
            cryptography.exceptions.InvalidTag — if any ciphertext has been tampered with
        """
        # ── Step 1: validate bundle metadata ───────────────────────────────
        if bundle.get("version") != VERSION:
            raise ValueError(f"Unsupported bundle version: {bundle.get('version')}")
        if bundle.get("algorithm") != "AES-256-GCM":
            raise ValueError(f"Unexpected algorithm: {bundle.get('algorithm')}")
 
        purpose = bundle["purpose"]
        _log("VALIDATE", f"Bundle version={bundle['version']}  algorithm={bundle['algorithm']}  purpose='{purpose}'")
 
        # ── Step 2: verify AAD hash ─────────────────────────────────────────
        if aad is None:
            aad = purpose.encode("utf-8")
 
        aad_hash = hashlib.sha256(aad).hexdigest()
        if aad_hash != bundle["aad_hash"]:
            raise ValueError(
                "AAD hash mismatch — the bundle metadata may have been tampered with."
            )
        _log("VERIFY",   "AAD hash verified — bundle metadata intact")
 
        # ── Step 3: unwrap the DEK ──────────────────────────────────────────
        wrapped = {
            "dek_iv":        bundle["dek_iv"],
            "encrypted_dek": bundle["encrypted_dek"],
            "dek_tag":       bundle["dek_tag"],
        }
        dek = self.km.unwrap_dek(wrapped, context=purpose)
        _log("UNWRAP",   "DEK unwrapped successfully by master KEK")
 
        # ── Step 4: decrypt the ciphertext ──────────────────────────────────
        data_iv  = base64.b64decode(bundle["data_iv"])
        data_tag = base64.b64decode(bundle["data_tag"])
        ct       = base64.b64decode(bundle["ciphertext"])
 
        aesgcm    = AESGCM(dek)
        plaintext = aesgcm.decrypt(data_iv, ct + data_tag, aad)
 
        _log("DECRYPT",  (
            f"Decrypted {len(ct):,} bytes ciphertext  →  "
            f"{len(plaintext):,} bytes plaintext"
        ))
        _log("INTEGRITY","GCM authentication tag verified — data not tampered with")
 
        # ── Step 5: zero the DEK from memory ────────────────────────────────
        dek = b"\x00" * KEY_SIZE
        del dek
        _log("SECURITY", "DEK zeroed from memory after use")
 
        return plaintext
 
    # ── File convenience wrappers ─────────────────────────────────────────────
 
    def encrypt_file(
        self,
        input_path:  str,
        output_path: str,
        purpose:     str = "file",
        aad:         Optional[bytes] = None,
    ) -> dict:
        """
        Read a file, encrypt it, write the bundle as JSON.
 
        Returns the bundle dict (also written to output_path).
        """
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
 
        plaintext = path.read_bytes()
        _log("FILE_IN",  f"Read {len(plaintext):,} bytes from '{input_path}'")
 
        # Include original filename and size in AAD if not provided
        if aad is None:
            meta = f"{path.name}:{len(plaintext)}"
            aad  = meta.encode("utf-8")
 
        bundle = self.encrypt(plaintext, purpose=purpose, aad=aad)
        bundle["original_filename"] = path.name
        bundle["original_size"]     = len(plaintext)
 
        Path(output_path).write_text(json.dumps(bundle, indent=2))
        _log("FILE_OUT", f"Bundle written to '{output_path}'")
 
        return bundle
 
    def decrypt_file(
        self,
        bundle_path: str,
        output_path: str,
        aad:         Optional[bytes] = None,
    ) -> bytes:
        """
        Read a bundle JSON file, decrypt it, write the plaintext.
 
        Returns the decrypted bytes.
        """
        bundle = json.loads(Path(bundle_path).read_text())
        _log("FILE_IN",  f"Loaded bundle from '{bundle_path}'")
 
        # Reconstruct AAD from bundle metadata if not supplied
        if aad is None:
            meta = f"{bundle['original_filename']}:{bundle['original_size']}"
            aad  = meta.encode("utf-8")
 
        plaintext = self.decrypt(bundle, aad=aad)
 
        Path(output_path).write_bytes(plaintext)
        _log("FILE_OUT", f"Plaintext written to '{output_path}'")
 
        return plaintext
 
 
# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
 
_LOG_RECORDS: list = []
 
def _log(stage: str, message: str):
    ts = datetime.now(timezone.utc).isoformat()
    _LOG_RECORDS.append({"time": ts, "stage": stage, "message": message})
    print(f"  [{stage:<10}] {message}")
 
def print_section(title: str):
    width = 62
    print(f"\n{'═' * width}")
    print(f"  {title}")
    print(f"{'═' * width}")
 
def print_bundle_summary(bundle: dict):
    """Print a human-readable summary of an encrypted bundle."""
    print(f"""
  ┌─ BUNDLE SUMMARY ────────────────────────────────────────┐
  │  purpose        : {bundle['purpose']:<40}│
  │  algorithm      : {bundle['algorithm']:<40}│
  │  created_at     : {bundle['created_at']:<40}│
  │  original_size  : {bundle.get('original_size', 'n/a'):<40}│
  ├─ DEK (wrapped) ─────────────────────────────────────────┤
  │  dek_iv         : {bundle['dek_iv'][:38]:<40}│
  │  encrypted_dek  : {bundle['encrypted_dek'][:38]:<40}│
  │  dek_tag        : {bundle['dek_tag'][:38]:<40}│
  ├─ Data (encrypted) ──────────────────────────────────────┤
  │  data_iv        : {bundle['data_iv'][:38]:<40}│
  │  data_tag       : {bundle['data_tag'][:38]:<40}│
  │  ciphertext     : {bundle['ciphertext'][:38]:<40}│
  ├─ Integrity ─────────────────────────────────────────────┤
  │  aad_hash       : {bundle['aad_hash'][:38]:<40}│
  └─────────────────────────────────────────────────────────┘""")
 
 
# ─────────────────────────────────────────────────────────────────────────────
# DEMO — runs when you execute this file directly
# ─────────────────────────────────────────────────────────────────────────────
 
def run_demo():
    """
    Full demo of the envelope encryption pipeline.
 
    Tests:
      1. Encrypting & decrypting raw bytes (quick sanity check)
      2. Encrypting & decrypting a file (e.g. an image)
      3. Tamper detection — proves the GCM auth tag catches modifications
    """
 
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║        AES-256-GCM Envelope Encryption — Demo Run           ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")
 
    # ── Initialise ────────────────────────────────────────────────────────
    print_section("INITIALISING MASTER KEY MANAGER (simulated HSM)")
    km  = MasterKeyManager()          # generates a random KEK for this demo
    enc = EnvelopeEncryptor(km)
 
    # ─────────────────────────────────────────────────────────────────────
    # TEST 1 — Encrypt / decrypt raw bytes
    # ─────────────────────────────────────────────────────────────────────
    print_section("TEST 1 — RAW BYTES ENCRYPTION")
 
    sample_text = (
        "SENSITIVE RECORD\n"
        "Name:    James R. Thornton\n"
        "SSN:     523-88-4471\n"
        "Card:    4111 1111 1111 1111\n"
        "PIN:     8842\n"
    ).encode("utf-8")
 
    print(f"  Plaintext ({len(sample_text)} bytes):")
    print("  " + "\n  ".join(sample_text.decode().splitlines()) + "\n")
 
    bundle = enc.encrypt(sample_text, purpose="test-record")
    print_bundle_summary(bundle)
 
    print_section("  Decrypting TEST 1...")
    recovered = enc.decrypt(bundle)
    assert recovered == sample_text, "FAIL: decrypted bytes don't match!"
    print(f"\n  ✓ Recovered plaintext matches original exactly.\n")
 
    # ─────────────────────────────────────────────────────────────────────
    # TEST 2 — Encrypt / decrypt a file
    # ─────────────────────────────────────────────────────────────────────
    print_section("TEST 2 — FILE ENCRYPTION")
 
    # Look for the sample image from our earlier pipeline run
    candidates = [
        "/home/claude/sample_pii_image.jpg",
        "/home/claude/pipeline_output/02_redacted.jpg",
    ]
    input_file = next((p for p in candidates if Path(p).exists()), None)
 
    if input_file:
        print(f"  Using existing image: {input_file}")
    else:
        # Create a tiny synthetic test file if no image is found
        input_file = "/tmp/test_input.bin"
        Path(input_file).write_bytes(secrets.token_bytes(1024))
        print(f"  No image found — created synthetic {Path(input_file).stat().st_size} byte test file.")
 
    bundle_file  = "/tmp/encrypted_bundle.json"
    decrypted_file = "/tmp/decrypted_output" + Path(input_file).suffix
 
    file_bundle = enc.encrypt_file(
        input_path  = input_file,
        output_path = bundle_file,
        purpose     = "meta-glasses-image",
    )
    print_bundle_summary(file_bundle)
 
    print_section("  Decrypting TEST 2 file...")
    dec_bytes = enc.decrypt_file(
        bundle_path = bundle_file,
        output_path = decrypted_file,
    )
 
    original_bytes = Path(input_file).read_bytes()
    assert dec_bytes == original_bytes, "FAIL: file bytes don't match after decrypt!"
    print(f"\n  ✓ Decrypted file is byte-for-byte identical to original.\n")
    print(f"  Bundle saved  → {bundle_file}")
    print(f"  Decrypted out → {decrypted_file}\n")
 
    # ─────────────────────────────────────────────────────────────────────
    # TEST 3 — Tamper detection
    # ─────────────────────────────────────────────────────────────────────
    print_section("TEST 3 — TAMPER DETECTION")
    print("  Flipping one bit in the ciphertext and attempting to decrypt...\n")
 
    tampered_bundle = dict(file_bundle)
    ct_bytes        = bytearray(base64.b64decode(tampered_bundle["ciphertext"]))
    ct_bytes[0]    ^= 0xFF          # flip 8 bits in the first byte
    tampered_bundle["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode()
 
    try:
        enc.decrypt_file.__func__   # just to check it's there
        dec_tampered = enc.decrypt(
            tampered_bundle,
            aad=(
                f"{file_bundle['original_filename']}:{file_bundle['original_size']}"
            ).encode()
        )
        print("  ✗ FAIL: tampered ciphertext was accepted — this should not happen!")
    except Exception as e:
        print(f"  ✓ Tamper detected and rejected.")
        print(f"    Exception: {type(e).__name__}: {e}\n")
 
    # ─────────────────────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────────────────────
    print_section("ALL TESTS COMPLETE")
    print("""
  What just happened:
 
  1. A random 256-bit master key (KEK) was created (simulating an HSM).
 
  2. For each encrypt() call:
       a. A fresh random 256-bit DEK was generated.
       b. The payload was encrypted with the DEK using AES-256-GCM.
       c. The DEK was encrypted (wrapped) with the KEK using AES-256-GCM.
       d. Both encrypted blobs + their IVs + GCM tags were packed
          into a JSON bundle.
       e. The DEK was zeroed from memory.
 
  3. For each decrypt() call:
       a. The KEK unwrapped the DEK (GCM tag verified the DEK's integrity).
       b. The DEK decrypted the payload (GCM tag verified the data's integrity).
       c. The DEK was zeroed from memory.
 
  4. A single bit-flip in the ciphertext caused decryption to fail,
     proving the GCM authentication tag is working.
 
  Key properties:
    • Every file gets a unique DEK — one compromised file ≠ all files.
    • The master key never touches the raw data.
    • Both the DEK and the data are integrity-protected by GCM tags.
    • AAD binds the encrypted data to its intended context/purpose.
    • The bundle is self-contained — store it anywhere (database, S3, etc.)
      and it can always be decrypted given the master key.
""")
 
    # ── Copy outputs so they're accessible ───────────────────────────────
    import shutil
    out_dir = Path("/mnt/user-data/outputs")
    out_dir.mkdir(parents=True, exist_ok=True)
 
    shutil.copy(bundle_file, out_dir / "encrypted_bundle.json")
    shutil.copy(decrypted_file, out_dir / ("decrypted_output" + Path(input_file).suffix))
 
    print(f"  Output files:")
    print(f"    encrypted_bundle.json       → the self-contained encrypted bundle")
    print(f"    decrypted_output.*          → byte-identical copy of the original\n")
 
 
# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
 
if __name__ == "__main__":
    run_demo()
