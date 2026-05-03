const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Health check
app.get("/", (req, res) => {
    res.send("✅ Android Attestation PoC Backend Running");
});

// Attestation API
app.post("/verify-attestation", (req, res) => {
    try {
        const { nonce, certificateChain } = req.body;

        // Basic validation
        if (!nonce || !certificateChain) {
            return res.status(400).json({
                success: false,
                error: "Missing nonce or certificateChain"
            });
        }

        if (!Array.isArray(certificateChain) || certificateChain.length === 0) {
            return res.status(400).json({
                success: false,
                error: "certificateChain must be a non-empty array"
            });
        }

        console.log("✅ Received Attestation Request");
        console.log("Nonce:", nonce);
        console.log("Certificates:", certificateChain.length);

        // Placeholder validation result
        const result = {
            success: true,
            message: "Attestation request received",
            details: {
                nonceReceived: nonce,
                certCount: certificateChain.length
            }
        };

        res.json(result);

    } catch (error) {
        console.error("❌ Error:", error);

        res.status(500).json({
            success: false,
            error: "Internal server error"
        });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
