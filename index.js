const express = require("express");
const crypto = require("crypto");
const forge = require("node-forge");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// In-memory nonce store (PoC)
const nonceStore = new Map();

// Health check
app.get("/", (req, res) => {
    res.send("✅ Backend Running");
});

// Generate nonce
app.get("/generate-nonce", (req, res) => {
    const nonce = crypto.randomBytes(16).toString("base64");
    nonceStore.set(nonce, true);
    res.json({ nonce });
});

// Verify attestation
app.post("/verify-attestation", (req, res) => {
    try {
        const { nonce, certificateChain } = req.body;

        if (!nonce || !certificateChain) {
            return res.status(400).json({
                success: false,
                error: "Missing nonce or certificateChain"
            });
        }

        if (!nonceStore.has(nonce)) {
            return res.status(400).json({
                success: false,
                error: "Invalid nonce"
            });
        }

        // 🔹 Decode leaf certificate
        const leafCertBase64 = certificateChain[0];
        const leafDer = Buffer.from(leafCertBase64, "base64");

        const certAsn1 = forge.asn1.fromDer(leafDer.toString("binary"));
        const cert = forge.pki.certificateFromAsn1(certAsn1);

        // 🔹 Find attestation extension
        const ext = cert.extensions.find(e =>
            e.id === "1.3.6.1.4.1.11129.2.1.17"
        );

        if (!ext) {
            return res.status(400).json({
                success: false,
                error: "Attestation extension not found"
            });
        }

        // 🔥 SAFE EXTRACTION (NO CRASH VERSION)

        // Step 1: Convert binary safely
        const extBuffer = Buffer.from(ext.value, "binary");

        // Step 2: Remove ASN.1 OCTET STRING header manually
        // First byte = 0x04 (OCTET STRING)
        // Second byte = length (may be multi-byte)

        let offset = 2;

        // Handle long-form length
        if (extBuffer[1] & 0x80) {
            const lengthBytes = extBuffer[1] & 0x7F;
            offset = 2 + lengthBytes;
        }

        const innerDer = extBuffer.slice(offset);

        // Step 3: Parse inner ASN.1 safely
        let attestationAsn1;
        try {
            attestationAsn1 = forge.asn1.fromDer(innerDer.toString("binary"));
        } catch (e) {
            return res.status(400).json({
                success: false,
                error: "ASN.1 parsing failed (device may not support full attestation)"
            });
        }

        const seq = attestationAsn1.value;

        if (!seq || seq.length < 5) {
            return res.status(400).json({
                success: false,
                error: "Invalid attestation structure"
            });
        }

        // 🔥 Extract challenge
        const challengeNode = seq[4];

        let extractedNonce = "";

        try {
            extractedNonce = Buffer.from(
                challengeNode.value,
                "binary"
            ).toString("base64");
        } catch (e) {
            return res.status(400).json({
                success: false,
                error: "Failed to extract nonce"
            });
        }

        console.log("🔹 Server nonce:", nonce);
        console.log("🔹 Extracted nonce:", extractedNonce);

        // 🔥 Compare nonce
        if (extractedNonce !== nonce) {
            return res.status(400).json({
                success: false,
                error: "Nonce mismatch ❌"
            });
        }

        // Remove nonce after use
        nonceStore.delete(nonce);

        return res.json({
            success: true,
            message: "✅ Attestation VERIFIED (nonce match)"
        });

    } catch (err) {
        console.error("Verification error:", err);

        return res.status(500).json({
            success: false,
            error: "Verification failed"
        });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
