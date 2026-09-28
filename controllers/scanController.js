const Scan = require('../models/Scan');
const whois = require('whois-json');
const axios = require('axios');
const crypto = require('crypto');

// 1. Phishing & WHOIS Domain Inspector
exports.scanUrl = async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ message: 'URL is required' });

  let riskScore = 0;
  let details = [];

  try {
    // Extract domain name from URL
    let parsedUrl = url.replace(/^(?:https?:\/\/)?/i, "").split('/')[0];

    // --- CHECK A: Punycode / Homograph Spoofing ---
    if (parsedUrl.includes('xn--')) {
      riskScore += 60;
      details.push('Punycode Detected: Potential Cyrillic/homograph domain spoofing.');
    }

    // --- CHECK B: Protocol & IP Check ---
    if (!url.startsWith('https://')) {
      riskScore += 15;
      details.push('Insecure Protocol: Missing HTTPS.');
    }
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(parsedUrl)) {
      riskScore += 40;
      details.push('Raw IP Address used instead of standard domain name.');
    }

    // --- CHECK C: WHOIS Birthday / Domain Age Detective ---
    try {
      const whoisData = await whois(parsedUrl);
      const creationDateStr = whoisData.creationDate || whoisData.created || whoisData.createdDate;

      if (creationDateStr) {
        const creationDate = new Date(creationDateStr);
        const ageInDays = Math.floor((new Date() - creationDate) / (1000 * 60 * 60 * 24));

        if (ageInDays < 30) {
          riskScore += 50;
          details.push(`CRITICAL WHOIS ALERT: Domain registered recently (${ageInDays} days ago). High phishing risk!`);
        } else if (ageInDays < 180) {
          riskScore += 25;
          details.push(`WHOIS Warning: Domain registered less than 6 months ago (${ageInDays} days).`);
        } else {
          details.push(`WHOIS Verified: Domain age is ${Math.floor(ageInDays / 365)} years old.`);
        }
      } else {
        details.push('WHOIS Warning: Domain registration date hidden or unavailable.');
      }
    } catch (whoisErr) {
      details.push('WHOIS Lookup: Unable to query domain birth certificate.');
    }

    let status = 'Safe';
    if (riskScore >= 50) status = 'Dangerous';
    else if (riskScore > 0) status = 'Warning';

    const scan = await Scan.create({
      user: req.user.id,
      type: 'url',
      target: url,
      riskScore,
      status,
      details
    });

    res.status(201).json(scan);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// 2. Real HaveIBeenPwned (HIBP) Password Breach Inspector
exports.scanPassword = async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ message: 'Password is required' });

  // Compute SHA-1 hash in uppercase
  const sha1Hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = sha1Hash.substring(0, 5); // First 5 chars for k-Anonymity
  const suffix = sha1Hash.substring(5);    // Remaining hash

  let pwnedCount = 0;
  let details = [];

  try {
    // Query HaveIBeenPwned API directly using 5-char prefix
    const hibpRes = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`);
    const hashes = hibpRes.data.split('\n');

    // Look for our suffix in HIBP bucket response
    const match = hashes.find(line => line.startsWith(suffix));
    if (match) {
      pwnedCount = parseInt(match.split(':')[1].trim(), 10);
      details.push(`BREACH ALERT: Password appeared in ${pwnedCount.toLocaleString()} known data leaks on HaveIBeenPwned!`);
    } else {
      details.push('NO BREACH FOUND: Password does not appear in known HaveIBeenPwned breach databases.');
    }

    let status = pwnedCount > 0 ? 'Dangerous' : 'Safe';
    let riskScore = pwnedCount > 0 ? 100 : 0;

    const scan = await Scan.create({
      user: req.user.id,
      type: 'password',
      target: `${prefix}*** (${password.length} chars)`,
      riskScore,
      status,
      details
    });

    res.status(201).json({ scan, pwnedCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.getScanHistory = async (req, res) => {
  try {
    const history = await Scan.find({ user: req.user.id }).sort({ createdAt: -1 });
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};// 3. Delete a specific scan item by ID
exports.deleteScan = async (req, res) => {
  try {
    const scan = await Scan.findOneAndDelete({ _id: req.params.id, user: req.user.id });
    if (!scan) return res.status(404).json({ message: 'Scan record not found' });
    res.json({ message: 'Scan audit record deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// 4. Submit Telemetry Phishing Report (For Step 4 in Command Center)
exports.reportTelemetry = async (req, res) => {
  const { targetUrl } = req.body;
  try {
    const scan = await Scan.create({
      user: req.user.id,
      type: 'url',
      target: targetUrl || 'Reported Phishing Telemetry',
      riskScore: 100,
      status: 'Dangerous',
      details: ['User-submitted telemetry report filed to Kavacham Threat Intelligence Ledger.']
    });
    res.status(201).json({ message: 'Telemetry telemetry report filed successfully', scan });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};