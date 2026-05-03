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

        // 🔹 Step 1: Validate input
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

        console.log("==================================");
        console.log("📥 Incoming Request");
        console.log("Nonce from client:", nonce);
        console.log("Cert chain length:", certificateChain.length);

        // 🔹 Step 2: Decode cert
        const leafCertBase64 = certificateChain[0];
        const leafDer = Buffer.from(leafCertBase64, "base64");

        const certAsn1 = forge.asn1.fromDer(leafDer.toString("binary"));
        const cert = forge.pki.certificateFromAsn1(certAsn1);

        // 🔹 Step 3: Find extension
        const ext = cert.extensions.find(e =>
            e.id === "1.3.6.1.4.1.11129.2.1.17"
        );

        if (!ext) {
            return res.status(400).json({
                success: false,
                error: "Attestation extension not found"
            });
        }

        // 🔹 Step 4: Safe ASN.1 unwrap
        const extBuffer = Buffer.from(ext.value, "binary");

        let offset = 2;
        if (extBuffer[1] & 0x80) {
            const lengthBytes = extBuffer[1] & 0x7F;
            offset = 2 + lengthBytes;
        }

        const innerDer = extBuffer.slice(offset);

        const attestationAsn1 = forge.asn1.fromDer(innerDer.toString("binary"));
        const seq = attestationAsn1.value;

        const challengeNode = seq[4];

        const extractedNonce = Buffer.from(
            challengeNode.value,
            "binary"
        ).toString("base64");

        console.log("🔹 Extracted nonce:", extractedNonce);
        console.log("🔹 Server nonce   :", nonce);

        // 🔹 Step 5: Compare (safe normalize)
        const normalize = (s) => s.replace(/=+$/, "").trim();

        if (normalize(extractedNonce) !== normalize(nonce)) {
            console.log("❌ NONCE MISMATCH");

            return res.status(400).json({
                success: false,
                error: "Nonce mismatch",
                debug: {
                    serverNonce: nonce,
                    extractedNonce: extractedNonce
                }
            });
        }

        console.log("✅ NONCE MATCH SUCCESS");

        nonceStore.delete(nonce);

        return res.json({
            success: true,
            message: "✅ Attestation VERIFIED"
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
