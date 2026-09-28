const mongoose = require('mongoose');

const ScanSchema = new mongoose.Schema(
  {
    user: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User', 
      required: true 
    },
    type: { 
      type: String, 
      enum: ['url', 'password'], 
      required: true 
    },
    target: { 
      type: String, 
      required: true 
    }, // Analyzed URL or masked password hash
    riskScore: { 
      type: Number, 
      required: true 
    }, // 0 to 100 (100 = High Threat)
    status: { 
      type: String, 
      enum: ['Safe', 'Warning', 'Dangerous'], 
      required: true 
    },
    details: [String] // Array of detected risk factors (e.g., "Punycode Homograph Detected", "Missing HTTPS")
  },
  { timestamps: true }
);

module.exports = mongoose.model('Scan', ScanSchema);