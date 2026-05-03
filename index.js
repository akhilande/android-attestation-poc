const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Health check
app.get("/", (req, res) => {
    res.send("✅ Android Attestation PoC Backend Running");
});

// Placeholder API (we will upgrade this next step)
app.post("/verify-attestation", (req, res) => {
    console.log("Received:", req.body);

    res.json({
        success: true,
        message: "Request received successfully (PoC step)"
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
