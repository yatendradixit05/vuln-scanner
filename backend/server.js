const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const mongoose   = require('mongoose');
const cors       = require('cors');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const scanRoutes = require('./routes/scans');
const { initQueue } = require('./queue');

const app    = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: ['http://localhost:5173', 'http://localhost:5174'], methods: ['GET', 'POST'] }
});

app.use(cors({ origin: ['http://localhost:5173', 'http://localhost:5174'] }));
app.use(express.json());

app.set('io', io);

app.use('/api/auth', authRoutes);
app.use('/api/scans', scanRoutes);

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  socket.on('join_scan', (scanId) => socket.join(scanId));
  socket.on('disconnect', () => console.log('Client disconnected'));
});

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/vuln-scanner')
  .then(() => {
    console.log('MongoDB connected');
    initQueue(io);
    server.listen(5000, () => console.log('Server running on port 5000'));
  })
  .catch(err => console.error('DB error:', err));