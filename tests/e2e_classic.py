#!/usr/bin/env python3
"""e2e_classic.py - mds-cpu against a fake midstate reference pool (ciphernom/midstate pool.rs
stratum, as run by midwimble.ariabrain.com): mining.subscribe -> true; mining.authorize
[address, worker, midwimble?] with the address parsed alone ("ADDRESS.worker" -> "Invalid
Address"); mining.notify [job_id, mining_hash, batch_template, share_target, height];
mining.submit [worker, job_id (u64), nonce]. Every share is checked with the reference walk.

  python3 tests/e2e_classic.py [seconds] [--win] [extra miner args...]"""
import ctypes, json, os, random, re, socket, subprocess, sys, threading, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LIBW = os.path.join(ROOT, 'build', 'libwalkref.so')
subprocess.check_call(['cc', '-O2', '-shared', '-fPIC', '-o', LIBW, os.path.join(ROOT, 'src', 'walk_ref.c')])
LW = ctypes.CDLL(LIBW)
def walk(mid, nonce):
    out = ctypes.create_string_buffer(32); LW.walk_hash(mid, ctypes.c_uint64(nonce), out); return out.raw

args = [a for a in sys.argv[1:]]
SECS = int(args.pop(0)) if args and args[0].isdigit() else 40
WIN = '--win' in args
if WIN: args.remove('--win')
ADDR = 'ab' * 36          # a hex address without dots
MW = os.environ.get('E2E_MW', '')

class Pool(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.srv = socket.socket(); self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(('127.0.0.1', 0)); self.srv.listen(4); self.port = self.srv.getsockname()[1]
        self.job = 1000; self.mid = os.urandom(32); self.target = bytes([0x00, 0x1f]) + b'\xff' * 30
        self.auths = []; self.ok = 0; self.bad = []; self.c = None; self.seen = set()
    def send(self, m): self.c.sendall((json.dumps(m) + '\n').encode())
    def notify(self):
        self.send({'id': None, 'method': 'mining.notify', 'params': [self.job, self.mid.hex(), {}, self.target.hex(), 372500 + self.job]})
    def run(self):
        while True:
            c, _ = self.srv.accept()
            try: self.serve(c)
            except Exception as e: print('pool: client gone:', e)
    def serve(self, c):
        self.c = c
        for line in c.makefile('r'):
            m = json.loads(line); p = m.get('params', [])
            if m['method'] == 'mining.subscribe': self.send({'id': m['id'], 'result': True, 'error': None})
            elif m['method'] == 'mining.authorize':
                self.auths.append(p)
                if not re.fullmatch(r'[0-9a-fA-F]{64,80}', p[0] if p else ''):
                    self.send({'id': m['id'], 'result': False, 'error': 'Invalid Address'}); continue
                self.send({'id': m['id'], 'result': True, 'error': None}); self.notify()
            elif m['method'] == 'mining.submit':
                worker, jid, nonce = p
                assert isinstance(jid, int) and isinstance(nonce, int), p
                if jid != self.job: self.send({'id': m['id'], 'result': False, 'error': 'Stale job'}); continue
                if (jid, nonce) in self.seen: self.send({'id': m['id'], 'result': False, 'error': 'Duplicate'}); continue
                self.seen.add((jid, nonce))
                h = walk(self.mid, nonce)
                if h < self.target: self.ok += 1; self.send({'id': m['id'], 'result': True, 'error': None})
                else: self.bad.append((jid, nonce)); self.send({'id': m['id'], 'result': False, 'error': 'Low difficulty'})

pool = Pool(); pool.start()
# E2E_FAILBACK=1: a first pool that comes up after 8 s (the miner starts on the fake pool as fallback)
FB = None
if os.environ.get('E2E_FAILBACK') == '1':
    s0 = socket.socket(); s0.bind(('127.0.0.1', 0)); FBPORT = s0.getsockname()[1]; s0.close()
    def late():
        time.sleep(8); global FB; FB = Pool(); FB.srv.close()
        FB.srv = socket.socket(); FB.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); FB.srv.bind(('127.0.0.1', FBPORT)); FB.srv.listen(4); FB.start()
    threading.Thread(target=late, daemon=True).start()
exe = ['wine', os.path.join(ROOT, 'build', 'win', 'mds-cpu.exe')] if WIN else [os.path.join(ROOT, 'build', 'lin', 'mds-cpu')]
cmd = exe + (['--pool', 'stratum+tcp://127.0.0.1:1'] if os.environ.get('E2E_DEADFIRST') == '1' else []) + (['--pool', 'stratum+tcp://127.0.0.1:%d' % FBPORT, '--failback', '20'] if FB is None and os.environ.get('E2E_FAILBACK') == '1' else []) + ['--pool', 'stratum+tcp://127.0.0.1:%d' % pool.port, '--user', ADDR + '.rig7', '--threads', '2', '--stats', '15', '--pool-log'] + \
      (['--pass', MW] if MW else []) + args
env = dict(os.environ, WINEDEBUG='-all')
p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
out = []
threading.Thread(target=lambda: [out.append(l) or sys.stdout.write('  | ' + l) for l in p.stdout], daemon=True).start()
t0 = time.time(); tj = t0
while time.time() - t0 < SECS and p.poll() is None:
    time.sleep(0.5)
    if pool.c and (pool.ok or (FB is not None and FB.ok)) and time.time() - tj > 12:
        for pl in [pool] + ([FB] if FB is not None and FB.c else []):
            try: pl.job += 1; pl.mid = os.urandom(32); pl.notify()
            except OSError: pass
        tj = time.time()
p.terminate()
try: p.wait(timeout=20)
except Exception: p.kill()
text = ''.join(out)
print('\n=== authorize params: %s' % pool.auths[:2])
print('=== shares ok %d, bad %d' % (pool.ok, len(pool.bad)))
if FB is not None: print('=== first pool after failback: shares ok %d, bad %d' % (FB.ok, len(FB.bad)))
fails = []
if not pool.auths or pool.auths[0][:2] != [ADDR, 'rig7']: fails.append('authorize params')
if MW and (len(pool.auths[0]) < 3 or pool.auths[0][2] != MW): fails.append('midwimble address not sent')
if pool.ok < 3: fails.append('too few shares')
if os.environ.get('E2E_FAILBACK') == '1' and (FB is None or FB.ok < 3): fails.append('no shares on the first pool after failback')
if pool.bad: fails.append('bad shares')
if 'Midstate Walk' not in text: fails.append('no Walk')
print('E2E CLASSIC RESULT:', 'ALL OK' if not fails else 'FAIL ' + '; '.join(fails))
sys.exit(1 if fails else 0)
