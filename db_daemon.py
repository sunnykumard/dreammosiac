import sys, json, sqlite3, os

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'dreammosaic.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

for line in sys.stdin:
    if not line.strip():
        continue
    try:
        req = json.loads(line)
        action, sql = req.get('action'), req.get('sql')
        params = req.get('params', [])
        cur = conn.cursor()
        if action == 'query':
            cur.execute(sql, params)
            res = {'status': 'ok', 'rows': [dict(r) for r in cur.fetchall()]}
        elif action == 'exec':
            cur.execute(sql, params)
            conn.commit()
            res = {'status': 'ok', 'lastrowid': cur.lastrowid, 'changes': cur.rowcount}
        elif action == 'exec_many':
            cur.executemany(sql, params)
            conn.commit()
            res = {'status': 'ok', 'changes': cur.rowcount}
        else:
            res = {'status': 'error', 'message': f'Unknown action: {action}'}
    except Exception as e:
        res = {'status': 'error', 'message': str(e)}
    sys.stdout.write(json.dumps(res) + '\n')
    sys.stdout.flush()
