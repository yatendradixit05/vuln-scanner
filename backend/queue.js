const { spawn } = require('child_process');
const path = require('path');
const Scan = require('./models/Scan');

let io;

function initQueue(socketIo) {
  io = socketIo;
}

async function addToQueue(scanId) {
  const scan = await Scan.findById(scanId);
  if (!scan) return;

  await Scan.findByIdAndUpdate(scanId, { status: 'running', phase: 'Phase A: Recon' });
  io.to(scanId.toString()).emit('scan_update', { status: 'running', phase: 'Phase A: Recon', progress: 0 });

  const enginePath = path.join(__dirname, '..', 'engine', 'main.py');
  const pythonExe = process.env.PYTHON_PATH || 'python3';

  const python = spawn(pythonExe, [enginePath, scan.targetUrl, scanId.toString()]);

  python.stdout.on('data', (data) => {
    const lines = data.toString().trim().split('\n');
    for (const line of lines) {
      try {
        const msg = JSON.parse(line.trim());
        io.to(scanId.toString()).emit('scan_update', msg);
        if (msg.finding) {
          Scan.findByIdAndUpdate(scanId, { $push: { findings: msg.finding } }).exec();
        }
        if (msg.phase || msg.progress !== undefined) {
          Scan.findByIdAndUpdate(scanId, {
            ...(msg.phase    ? { phase: msg.phase }       : {}),
            ...(msg.progress !== undefined ? { progress: msg.progress } : {})
          }).exec();
        }
      } catch (_) {}
    }
  });

  python.stderr.on('data', (data) => {
    console.error('Python error:', data.toString());
  });

  python.on('close', async (code) => {
    const status = code === 0 ? 'completed' : 'failed';
    await Scan.findByIdAndUpdate(scanId, { status, completedAt: new Date(), progress: 100 });
    io.to(scanId.toString()).emit('scan_update', { status, progress: 100 });
    console.log(`Scan ${scanId} ${status} (exit code ${code})`);
  });
}

module.exports = { initQueue, addToQueue };