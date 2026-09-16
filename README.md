# ZeroSecurity

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero External Dependencies](https://img.shields.io/badge/Dependencies-0%20External-brightgreen.svg)]()
[![Multi-Targeting](https://img.shields.io/badge/.NET-8.0%20%7C%204.6.2%20%7C%20Standard%202.0-orange.svg)]()
[![Tests: 9 Passed](https://img.shields.io/badge/Tests-9%20Passed%20(100%25)-brightgreen.svg)]()

> **Architectural Standard**: 100% Pure C#, Zero External Dependencies, Multi-Targeting across `.NET 8.0`, `.NET Framework 4.6.2`, and `.NET Standard 2.0`.

`ZeroSecurity` is the sovereign, high-throughput cryptographic and cyber-defense foundation of the **ZeroUniverse** ecosystem. It provides low-overhead, zero-allocation algorithms for hashing, multi-pattern signature matching, IOC threat intelligence lookups, Shannon byte entropy, streaming UEBA anomaly mathematics, and pure managed authenticated encryption.

---

## 🏛️ Architecture & Capabilities

```
ZeroSecurity/
├── Hashing/
│   ├── Blake3.cs               # Pure C# 256-bit BLAKE3 tree hash (zero-alloc on chunks <= 1024B)
│   ├── SsdeepFuzzyHash.cs      # Context-Triggered Piecewise Hashing (CTPH) malware similarity
│   └── FastSha256.cs           # Pure managed FIPS 180-4 SHA-256 operating over ReadOnlySpan<byte>
├── Matching/
│   ├── BloomFilter.cs          # Double-hashing (Kirsch-Mitzenmacher) filter for millions of IOCs
│   ├── AhoCorasick.cs          # Multi-pattern string/byte matching in a single linear pass O(N + M)
│   └── RadixIpTrie.cs          # Sub-microsecond IPv4 CIDR prefix matching for C2/Tor blacklists
├── Anomaly/
│   ├── ShannonEntropy.cs       # SIMD-vectorized entropy (0.0..8.0) for detecting Ransomware / Packers
│   └── WelfordStats.cs         # Online streaming mean, variance & Z-score in O(1) memory for UEBA
└── Crypto/
    └── ChaCha20Poly1305.cs     # Pure C# RFC 8439 AEAD cipher for quarantine file encryption
```

---

## ⚡ Key Modules

### 1. Hashing & Malware Fingerprinting
- **`Blake3`**: Up to 4x-10x faster than SHA-256. Single chunk inputs (&le; 1024 bytes) execute with **zero heap allocation**.
- **`SsdeepFuzzyHash`**: Compares modified binaries, script variants, and morphed malware samples. Produces standard `blocksize:hash1:hash2` signatures and calculates 0..100 similarity scores.
- **`FastSha256`**: Pure managed FIPS 180-4 implementation operating directly on `ReadOnlySpan<byte>` with no runtime CryptoAPI/CNG interop overhead.

### 2. IOC & Threat Matching
- **`BloomFilter`**: Sub-millisecond $O(1)$ set membership query across millions of threat hashes/domains with compact bit-array serialization.
- **`AhoCorasick`**: Scans process command-lines and memory payloads for thousands of keywords (e.g. LOLBAS, PowerShell scripts, malicious strings) simultaneously in a single pass.
- **`RadixIpTrie`**: Sub-microsecond Longest Prefix Matching (LPM) for IP/CIDR threat tags (e.g. Tor Exit Nodes, Cobalt Strike C2s).

### 3. Anomaly & Behavioral Mathematics (UEBA)
- **`ShannonEntropy`**: Computes mathematical entropy over arbitrary buffers. Values $\ge 7.2$ reliably flag encrypted ransomware payloads or packed executables.
- **`WelfordStats`**: Calculates real-time streaming population mean, sample variance, standard deviation, and Z-scores without storing historical data, enabling lightweight anomaly detection on industrial endpoints.

### 4. Sovereign Cryptography
- **`ChaCha20Poly1305`**: Pure C# RFC 8439 AEAD cipher. Provides fast, memory-safe encryption and authentication tags for isolating malware into quarantine vaults or securing ZeroWire communication channels.

---

## 🚀 Quick Usage

```csharp
using ZeroSecurity.Anomaly;
using ZeroSecurity.Hashing;
using ZeroSecurity.Matching;

// 1. BLAKE3 Hashing
Span<byte> hash = stackalloc byte[32];
Blake3.Hash(payloadBytes, hash);

// 2. Ransomware Detection via Shannon Entropy
if (ShannonEntropy.IsLikelyEncryptedOrPacked(fileBuffer, threshold: 7.2))
{
    Console.WriteLine("Warning: File exhibits high entropy consistent with ransomware encryption.");
}

// 3. IOC Membership Check
var bloom = new BloomFilter(expectedElements: 500_000, falsePositiveRate: 0.01);
bloom.Add("bad-actor-domain.com");
bool isThreat = bloom.Contains("bad-actor-domain.com"); // true
```

---

## 📄 License
Released under the **MIT License**. Part of the **ZeroPlatform** sovereign industrial computing framework.
