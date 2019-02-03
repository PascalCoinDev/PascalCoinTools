# PascalCoin KeyTool

# What Does This Tool Do?

```
PascalCoin KeyTool is a simple tool that supports

1. Generation of Key Pairs Using the Curves Supported by PascalCoin Desktop Wallet.

2. Supports a Stress Test Mode that generates Key Pairs (of Supported Curves),
   Signs a Message (and Verify the Generated Signature).
   
3. Encryption/Decryption Of PrivateKeys in conformance with PascalCoin Desktop Wallet Standard.

4. Encryption/Decryption of Payloads (Password) with PascalCoin Desktop Wallet Standard.

5. Encryption/Decryption of Payloads (ECIES) with PascalCoin Desktop Wallet Standard.

This tool can decrypt existing PascalCoin payloads for (No 3 and 4).

```

# Build Instructions

**Lazarus/FPC**
```
1. Install Lazarus/FPC Compiler (At Least Lazarus 1.8.2 and FPC 3.0.4).
2. Open/Install [CryptoLib4Pascal](https://github.com/Xor-el/CryptoLib4Pascal) and its dependencies in Lazarus.
3. Open "PascalCoinKeyTool.lpi" in Lazarus and Build.

```

**Delphi (FMX)**

Thanks to Russell Weetch (UrbanCohort on PascalCoin Discord for the FMX Version).
```
1. Install Delphi Compiler (At Least XE6 and Above).
2. Open "FMXPascalCoinKeyTool.dpr" in Delphi.
3. Add [CryptoLib4Pascal](https://github.com/Xor-el/CryptoLib4Pascal) and its dependencies to the project search path.
4. Build.

```

# License

This "Software" is Licensed Under  **`MIT License (MIT)`** .
