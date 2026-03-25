"""
run.py — Entry point for the reversible blur tool.

HOW TO USE:
  1. Put your image in this folder.
  2. Change YOUR_IMAGE.jpg below to your actual filename.
  3. Run:  python run.py
"""

from pathlib import Path
from blur_unblur import blur, unblur

# ── EDIT THIS ──────────────────────────────────────────────────────────────
IMAGE = "YOUR_IMAGE.jpg"      # ← change to your image filename
BLUR_RADIUS = 25              # 1–50, higher = more blurred (25 is strong)
# ──────────────────────────────────────────────────────────────────────────

# Derived output filenames (no need to change these)
image_stem     = Path(IMAGE).stem
image_ext      = Path(IMAGE).suffix
BLURRED        = f"{image_stem}_blurred{image_ext}"
ENCRYPTED      = f"{image_stem}_encrypted.bin"
RESTORED       = f"{image_stem}_restored{image_ext}"

# ── Sanity check ───────────────────────────────────────────────────────────
if not Path(IMAGE).exists():
    print(f"\n  ERROR: '{IMAGE}' not found in this folder.")
    print(f"  → Copy your image into this folder and update the IMAGE variable above.\n")
    exit(1)

# ── Step 1: Blur + encrypt ─────────────────────────────────────────────────
print(f"\nStep 1 — Blurring and encrypting '{IMAGE}' ...")
key = blur(
    input_path     = IMAGE,
    blurred_path   = BLURRED,
    encrypted_path = ENCRYPTED,
    blur_radius    = BLUR_RADIUS,
)

print(f"  Encryption key (save this!): {key.hex()}\n")

# ── Step 2: Restore (simulating authorized access) ─────────────────────────
print(f"Step 2 — Restoring original from encrypted bundle ...")
unblur(
    blurred_path   = BLURRED,
    encrypted_path = ENCRYPTED,
    output_path    = RESTORED,
    key            = key,
)

# ── Done ───────────────────────────────────────────────────────────────────
print("Done! Check these files in your folder:")
print(f"  {BLURRED:<35} ← blurred (safe to share)")
print(f"  {ENCRYPTED:<35} ← encrypted original (needs key)")
print(f"  {RESTORED:<35} ← restored original\n")
print("To restore again in a new session, use:")
print(f'  key = bytes.fromhex("{key.hex()[:16]}...")')
print(f'  unblur("{BLURRED}", "{ENCRYPTED}", "{RESTORED}", key)\n')
