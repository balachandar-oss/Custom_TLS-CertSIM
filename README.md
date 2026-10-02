# Project CipherWire 🛡️

> A "Glass-Box" TLS Handshake & PKI Simulator built from bare metal to demystify internet cryptography.

Unlike standard applications that rely on high-level wrappers like `SSLSocket` or `HttpsURLConnection`, **CipherWire** touches the bare metal of the internet. It manually constructs raw TCP byte payloads, parses binary X.509 certificates, and performs native cryptographic math to establish a secure connection. 

This project was built to gain a deep, protocol-level understanding of network security, ASN.1 encoding, and Elliptic Curve Cryptography.

## ⚙️ Core Architecture

* **Phase 1: Raw Byte Assembly:** Constructs the `ClientHello` payload using strict Big-Endian network order, injecting SNI (Server Name Indication) and cryptographic nonces via `java.nio.ByteBuffer`.
* **Phase 2: Protocol Parsing:** Reads raw binary server responses and identifies TLS Record and Handshake boundaries, catching TLS 1.3 downgrade sentinels.
* **Phase 3: Custom ASN.1/DER Parser:** Implements a recursive TLV (Type-Length-Value) parser to deconstruct live X.509 certificates byte-by-byte, extracting Validity Dates, Subject Names, and raw Public Keys.
* **Phase 4: Independent PKI Trust Store:** Bypasses Java's native JKS in favor of a custom SQLite relational database to store Root CA public keys and natively verify `SHA256withECDSA` digital signatures.
* **Phase 5: Native ECDHE Key Exchange:** Extracts the server's ephemeral EC point and utilizes Java's `KeyAgreement` engine to mathematically derive a 32-byte shared master secret over the `secp256r1` curve.
* **Enterprise Auditing:** Silently logs handshake telemetry, negotiated ciphers, and cryptographic latency to a local SQLite audit ledger for network forensics.

## 🛠️ Tech Stack

* **Language:** Java 11+ (`java.net`, `java.nio`, `java.security`, `javax.crypto`)
* **Database:** SQLite (via JDBC)
* **Concepts:** RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2), ASN.1 DER encoding, X.509 PKI, Elliptic Curve Diffie-Hellman (ECDHE).

## 🚀 Quick Start

Ensure you have the SQLite JDBC driver in your project directory.

```bash
# 1. Compile the project
javac -cp ".;sqlite-jdbc-3.x.x.jar" CipherWireClient.java TrustStoreManager.java AuditLedger.java DerParser.java KeyExchangeManager.java

# 2. Execute the simulator
java -cp ".;sqlite-jdbc-3.x.x.jar" CipherWireClient google.com
