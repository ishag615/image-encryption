# image-encryption
AES-256-GCM ENVELOPE ENCRYPTION — Full Implementation             ║
║                                                                              ║
║  ARCHITECTURE                                                                ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║  Master Key (KEK)  →  wraps  →  Data Encryption Key (DEK)                   ║
║  Data Encryption Key (DEK)   →  encrypts  →  Plaintext                      ║
║                                                                              ║
║  The master key never touches the data directly.                             ║
║  Each piece of data gets its own unique DEK.                                 ║
║  The encrypted DEK travels with the ciphertext in the bundle.                ║
║                                                                              ║
║  BUNDLE FORMAT (JSON)                                                        ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║  {                                                                           ║
║    "version":       "1.0",                                                   ║
║    "algorithm":     "AES-256-GCM",                                           ║
║    "purpose":       <caller-supplied label>,                                 ║
║    "created_at":    <ISO timestamp>,                                         ║
║                                                                              ║
║    "dek_iv":        <base64>   ← random IV used to encrypt the DEK          ║
║    "dek_tag":       <base64>   ← GCM auth tag for DEK integrity             ║
║    "encrypted_dek": <base64>   ← the DEK, encrypted under the KEK          ║
║                                                                              ║
║    "data_iv":       <base64>   ← random IV used to encrypt the data         ║
║    "data_tag":      <base64>   ← GCM auth tag for data integrity            ║
║    "ciphertext":    <base64>   ← the encrypted payload                      ║
║                                                                              ║
║    "aad_hash":      <hex>      ← SHA-256 of the AAD for verification        ║
║  }                                                                           ║
║                                                                              ║
║  USAGE                                                                       ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║  python aes256gcm_envelope.py                                                ║
║    → runs the built-in demo: encrypts a sample image, decrypts it back,     ║
║      verifies integrity, and prints a full audit report.                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
