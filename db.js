const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');

class DatabaseClient {
  constructor() {
    this.process = null;
    this.rl = null;
    this.pendingQueue = [];
    this.initProcess();
  }

  initProcess() {
    const daemonPath = path.join(__dirname, 'db_daemon.py');
    this.process = spawn('python3', [daemonPath], {
      stdio: ['pipe', 'pipe', 'inherit']
    });

    this.rl = readline.createInterface({
      input: this.process.stdout,
      terminal: false
    });

    this.rl.on('line', (line) => {
      if (!line.trim()) return;
      const callback = this.pendingQueue.shift();
      if (!callback) return;
      try {
        const res = JSON.parse(line);
        if (res.status === 'ok') callback.resolve(res);
        else callback.reject(new Error(res.message || 'Database error'));
      } catch (err) { callback.reject(err); }
    });

    this.process.on('error', (err) => console.error('Database process error:', err));
    this.process.on('exit', (code) => {
      console.warn(`Database process exited with code ${code}. Restarting...`);
      setTimeout(() => this.initProcess(), 500);
    });
  }

  execute(action, sql, params = []) {
    return new Promise((resolve, reject) => {
      this.pendingQueue.push({ resolve, reject });
      const payload = JSON.stringify({ action, sql, params }) + '\n';
      this.process.stdin.write(payload);
    });
  }

  async query(sql, params = []) {
    const res = await this.execute('query', sql, params);
    return res.rows || [];
  }
  async queryOne(sql, params = []) {
    const rows = await this.query(sql, params);
    return rows.length > 0 ? rows[0] : null;
  }
  async exec(sql, params = []) {
    const res = await this.execute('exec', sql, params);
    return { lastrowid: res.lastrowid, changes: res.changes };
  }
  async execMany(sql, paramsList = []) {
    const res = await this.execute('exec_many', sql, paramsList);
    return { changes: res.changes };
  }
  close() { if (this.process) this.process.kill(); }
}
module.exports = new DatabaseClient();
