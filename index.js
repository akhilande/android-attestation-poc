const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// In-memory store (PoC only)
const nonceStore = new Map();

// Health
app.get("/", (req, res) => {
    res.send("✅ Backend Running");
});

// 🔐 Generate Nonce
app.get("/generate-nonce", (req, res) => {
    const nonce = crypto.randomBytes(16).toString("base64");

    // Store nonce (PoC: no expiry yet)
    nonceStore.set(nonce, true);

    res.json({ nonce });
});

// 🔍 Verify Attestation
app.post("/verify-attestation", (req, res) => {
    try {
        const { nonce, certificateChain } = req.body;

        if (!nonce || !certificateChain) {
            return res.status(400).json({
                success: false,
                error: "Missing nonce or certificateChain"
            });
        }

        // Check nonce exists
        if (!nonceStore.has(nonce)) {
            return res.status(400).json({
                success: false,
                error: "Invalid or unknown nonce"
            });
        }

        // (Later we will extract nonce from cert and compare)
        console.log("✅ Nonce verified from request");

        // Remove nonce after use (important)
        nonceStore.delete(nonce);

        res.json({
            success: true,
            message: "Nonce accepted (PoC stage)"
        });

    } catch (err) {
        res.status(500).json({ success: false, error: "Server error" });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
