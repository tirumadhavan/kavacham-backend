const express = require('express');
const router = express.Router();
const { scanUrl, scanPassword, getScanHistory, deleteScan, reportTelemetry } = require('../controllers/scanController');
const { protect } = require('../middleware/authMiddleware');

router.post('/url', protect, scanUrl);
router.post('/password', protect, scanPassword);
router.get('/history', protect, getScanHistory);
router.delete('/:id', protect, deleteScan);             // Delete route
router.post('/telemetry', protect, reportTelemetry);     // Telemetry route

module.exports = router;