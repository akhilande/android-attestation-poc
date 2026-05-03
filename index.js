const express = require("express");
const crypto = require("crypto");
const forge = require("node-forge");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// In-memory nonce store
const nonceStore = new Map();

// Health
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
                error: "Missing fields"
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

        // 🔹 Parse extension ASN.1
        const extAsn1 = forge.asn1.fromDer(ext.value);

        // Structure: SEQUENCE → elements
        const attestationSeq = extAsn1.value;

        // 🔥 attestationChallenge is at index 4
        const challengeNode = attestationSeq[4];

        const challengeBytes = challengeNode.value;

        // Convert to Base64 (same format as server nonce)
        const extractedNonce = Buffer.from(challengeBytes, "binary").toString("base64");

        console.log("🔹 Server nonce:", nonce);
        console.log("🔹 Extracted nonce:", extractedNonce);

        // 🔥 Compare
        if (extractedNonce !== nonce) {
            return res.status(400).json({
                success: false,
                error: "Nonce mismatch ❌"
            });
        }

        // Remove nonce after use
        nonceStore.delete(nonce);

        res.json({
            success: true,
            message: "✅ Attestation VERIFIED (nonce match)",
            details: {
                nonceMatch: true
            }
        });

    } catch (err) {
        console.error("Verification error:", err);
        res.status(500).json({
            success: false,
            error: "Verification failed"
        });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
