const mongoose = require('mongoose');

const FindingSchema = new mongoose.Schema({
  type:                 { type: String },
  severity:             { type: String, enum: ['Critical','High','Medium','Low','Info'] },
  url:                  { type: String },
  description:          { type: String },
  proof:                { type: String },
  fixSnippet:           { type: String },
  cvss_score:           { type: Number },
  ease_of_exploit:      { type: String },
  impact:               { type: String },
  remediation_priority: { type: String },
  screenshot:           { type: String },
});

const ScanSchema = new mongoose.Schema({
  targetUrl:   { type: String, required: true },
  status:      { type: String, enum: ['queued','running','completed','failed'], default: 'queued' },
  phase:       { type: String, default: 'queued' },
  progress:    { type: Number, default: 0 },
  findings:    [FindingSchema],
  reportPath:  { type: String },
  createdAt:   { type: Date, default: Date.now },
  completedAt: { type: Date },
});

module.exports = mongoose.model('Scan', ScanSchema);