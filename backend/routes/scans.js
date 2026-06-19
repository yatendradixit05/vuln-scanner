const express  = require('express');
const router   = express.Router();
const path     = require('path');
const fs       = require('fs');
const Scan     = require('../models/Scan');
const { addToQueue } = require('../queue');

router.post('/start', async (req, res) => {
  try {
    const { targetUrl } = req.body;
    if (!targetUrl) return res.status(400).json({ error: 'targetUrl required' });
    const scan = await Scan.create({ targetUrl });
    addToQueue(scan._id);
    res.json({ scanId: scan._id, message: 'Scan queued' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/:id/report', async (req, res) => {
  try {
    const reportPath = path.join(
      'C:\\Projects\\vuln-scanner\\engine\\reports',
      `report_${req.params.id}.pdf`
    );
    if (!fs.existsSync(reportPath))
      return res.status(404).json({ error: 'Report not found' });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition',
      `attachment; filename="vuln-report-${req.params.id}.pdf"`);
    fs.createReadStream(reportPath).pipe(res);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Not found' });
    res.json(scan);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/', async (req, res) => {
  try {
    const scans = await Scan.find().sort({ createdAt: -1 }).limit(50).select('-findings');
    res.json(scans);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;