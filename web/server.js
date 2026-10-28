/**
 * server.js — Kyber768 UI Backend
 *
 * Spawns kyber_interactive.exe --web as a child process.
 * Feeds it option + inputs via stdin, reads clean stdout back.
 *
 * Usage:
 *   npm install
 *   node server.js
 *   Open http://localhost:3000
 */

const express   = require('express');
const { spawn } = require('child_process');
const path      = require('path');
const fs        = require('fs');

const app  = express();
const PORT = 3000;

// ── Path to your compiled exe ─────────────────────────────────────
// Assumes this folder (kyber-ui) sits next to myoqs/
const EXE_PATH = path.resolve(__dirname, '..', 'build', 'kyber_interactive.exe');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Run the exe with --web flag, feed option + inputs via stdin ───
function runKyber(option, inputs = []) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(EXE_PATH)) {
      return reject(new Error(`Executable not found: ${EXE_PATH}`));
    }

    // Working directory = build folder so key/ct files land there
    const cwd   = path.dirname(EXE_PATH);
    const child = spawn(EXE_PATH, ['--web'], { stdio: ['pipe','pipe','pipe'], cwd });

    let output = '', errOutput = '';
    child.stdout.on('data', d => output     += d.toString());
    child.stderr.on('data', d => errOutput  += d.toString());

    child.on('close', code => {
      if (code !== 0 && errOutput) output += '\nERROR: ' + errOutput;
      resolve(output.trim());
    });
    child.on('error', err => reject(new Error(`Failed to start process: ${err.message}`)));

    try {
      // First line: the menu option number
      child.stdin.write(option.toString() + '\n');
      // Subsequent lines: the inputs for that option
      for (const inp of inputs) child.stdin.write(inp + '\n');
      child.stdin.end();
    } catch (err) {
      reject(new Error(`Failed to write stdin: ${err.message}`));
    }
  });
}

// ── POST /api/run ─────────────────────────────────────────────────
// Body: { option: 1|2|3, inputs: [...] }
app.post('/api/run', async (req, res) => {
  const { option, inputs = [] } = req.body;

  if (!option || !Number.isInteger(option) || option < 1 || option > 3) {
    return res.status(400).json({ success: false, error: 'Option must be 1, 2, or 3.' });
  }

  const required = { 1: 1, 2: 3, 3: 2 };
  if (inputs.length < required[option]) {
    return res.status(400).json({
      success: false,
      error: `Option ${option} needs ${required[option]} input(s), got ${inputs.length}.`
    });
  }

  try {
    console.log(`Running option ${option} with inputs:`, inputs);
    const output = await runKyber(option, inputs);
    console.log('Done:', output.split('\n')[0]);
    res.json({ success: true, output });
  } catch (err) {
    console.error('Error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── GET /api/health ───────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  const exists = fs.existsSync(EXE_PATH);
  res.json({ status: exists ? 'ready' : 'error', executable: exists ? 'found' : 'missing', path: EXE_PATH });
});

// ── Serve index.html ──────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
  console.log(`\n  Kyber768 server running at http://localhost:${PORT}`);
  console.log(`  EXE: ${EXE_PATH}`);
  console.log(`  Status: ${fs.existsSync(EXE_PATH) ? 'exe found' : 'WARNING: exe not found'}\n`);
});