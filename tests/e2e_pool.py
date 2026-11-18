#!/usr/bin/env python3
"""e2e_pool.py - end-to-end test of mds-cpu against a fake Midstate LuckyPool.

  python3 tests/e2e_pool.py [seconds] [--tls]

The fake pool speaks the LuckyPool dialect seen on eu.lproute.com (mining.auth, mining.notify
with blob/extranonce/target, mining.submit [worker, job_id, nonce_low_hex]) and verifies every
share with the full 1,000,001-compression chain (src/mds_pow.c)."""
import ctypes, json, os, random, socket, subprocess, sys, threading, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
LIB = os.path.join(ROOT, 'build', 'libmdspow.so')
subprocess.check_call(['cc', '-O2', '-shared', '-fPIC', '-o', LIB, os.path.join(ROOT, 'src', 'mds_pow.c')])
L = ctypes.CDLL(LIB)
WALK = os.environ.get('E2E_WALK') == '1'
LIBW = os.path.join(ROOT, 'build', 'libwalkref.so')
if WALK:
    subprocess.check_call(['cc', '-O2', '-shared', '-fPIC', '-o', LIBW, os.path.join(ROOT, 'src', 'walk_ref.c')])
    LW = ctypes.CDLL(LIBW)
def ext(mid, nonce):
    out = ctypes.create_string_buffer(32)
    if WALK and not (os.environ.get('E2E_SWITCH') == '1' and pool.job < 1760000002 and CUR_JOB_OF[0] < 1760000002):
        LW.walk_hash(mid, ctypes.c_uint64(nonce), out)
        return out.raw
    L.mds_extension(mid, ctypes.c_uint64(nonce), ctypes.c_uint32(1000000), out)
    return out.raw

CUR_JOB_OF = [0]
SECS = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 60
TLS = '--tls' in sys.argv
JOB_S = int(os.environ.get('E2E_JOB_S', '12'))   # new job every N s

class Pool(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.srv = socket.socket(); self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(('127.0.0.1', 0)); self.srv.listen(1); self.port = self.srv.getsockname()[1]
        self.job = 1760000000; self.mid = bytes(random.randrange(256) for _ in range(32))
        self.target = (bytes([0x00, 0x1f]) if WALK else bytes([0x00, 0x7f])) + b'\xff' * 30   # Walk 1/2048, chain 1/512
        self.xn = '%08x' % random.getrandbits(32)
        self.log = []; self.nonces = set(); self.auth = None; self.agent = None; self.c = None
        self.busy_once = True
        self.valid = {}          # job id -> mining hash still accepted (same block)
        self.clean = True
        self.valid['M%d' % self.job] = self.mid
        self.old_ok = 0          # accepted shares of a job that was no longer the newest
    def blob(self): return self.mid.hex() + '00000000' + self.xn
    def jobmsg(self):
        j = {'blob': self.blob(), 'clean': self.clean, 'extranonce': self.xn, 'job_id': 'M%d' % self.job, 'target': self.target.hex()}
        if WALK: j['height'] = (371400 if (os.environ.get('E2E_SWITCH') == '1' and self.job < 1760000002) else 372000) + self.job % 100
        return j
    def send(self, m): self.c.sendall((json.dumps(m) + '\n').encode())
    def run(self):
        while True:
            c, _ = self.srv.accept()
            try: self.serve(c)
            except Exception as e: print('pool: client gone:', e)
    def serve(self, c):
        if TLS:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain('/tmp/e2e.crt', '/tmp/e2e.key')
            c = ctx.wrap_socket(c, server_side=True)
        self.c = c; f = c.makefile('r')
        for line in f:
            m = json.loads(line)
            if m['method'] == 'mining.auth':
                u = m['params'][0]; addr, _, w = u.partition('.')
                self.auth = (addr, w); self.agent = m['params'][2]
                self.send({'id': m['id'], 'error': None, 'result': {'job': self.jobmsg(), 'ok': True, 'session_id': 'abcd'}})
            elif m['method'] == 'mining.submit':
                w, jid, lowhex = m['params']
                assert w == self.auth[1], (w, self.auth)
                assert len(lowhex) == 8, lowhex
                nonce = int.from_bytes(bytes.fromhex(lowhex) + bytes.fromhex(self.xn), 'little')
                if self.busy_once:
                    self.busy_once = False
                    self.send({'id': m['id'], 'result': None, 'error': [21, 'Verifier busy, retry', None]}); continue
                if jid not in self.valid: ok, err = False, [21, 'stale job', None]
                elif (jid, nonce) in self.nonces: ok, err = False, [22, 'duplicate share', None]
                else:
                    CUR_JOB_OF[0] = int(jid[1:])
                    h = ext(self.valid[jid], nonce)
                    if h < self.target: ok, err = True, None
                    else: ok, err = False, [23, 'invalid/low work', None]
                    if ok and jid != 'M%d' % self.job: self.old_ok += 1
                self.nonces.add((jid, nonce))
                self.log.append((jid, nonce, ok, err and err[1]))
                self.send({'id': m['id'], 'result': ok, 'error': err})
            else:
                self.send({'id': m['id'], 'result': None, 'error': [20, 'method not supported', None]})
    def new_job(self, clean=True):
        self.job += 1; self.mid = bytes(random.randrange(256) for _ in range(32)); self.clean = clean
        if clean: self.valid = {}
        self.valid['M%d' % self.job] = self.mid
        self.send({'id': None, 'method': 'mining.notify', 'params': [self.jobmsg()]})

if TLS and not os.path.exists('/tmp/e2e.crt'):
    subprocess.check_call(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', '/tmp/e2e.key', '-out', '/tmp/e2e.crt',
                           '-days', '2', '-subj', '/CN=localhost'], stderr=subprocess.DEVNULL)
pool = Pool(); pool.start()
url = ('stratum+ssl' if TLS else 'stratum+tcp') + '://127.0.0.1:%d' % pool.port
env = dict(os.environ, LD_LIBRARY_PATH=os.path.join(ROOT, 'build', 'sim'), WINEDEBUG='-all', WINEPREFIX='/tmp/wpfx')
WIN = '--win' in sys.argv
exe = ['wine', os.path.join(ROOT, 'build', 'win', 'mds-cpu.exe')] if WIN else [os.path.join(ROOT, 'build', 'lin', 'mds-cpu')]
cmd = exe + [ '--pool', url, '--user', 'MSSADDRESS.simrig', '--dialect', '2',
       '--threads', '2', '--stats', '15', '--verify-s', '5', '--pool-log', '--verbose'] + os.environ.get('E2E_ARGS', '').split() + (['--insecure'] if TLS else [])
print('running:', ' '.join(cmd))
p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=os.path.join(ROOT, 'build', 'win') if WIN else None)
out = []
def reader():
    for line in p.stdout: out.append(line); sys.stdout.write('  | ' + line)
threading.Thread(target=reader, daemon=True).start()
t0 = time.time(); tj = t0
while time.time() - t0 < SECS and p.poll() is None:
    time.sleep(0.5)
    if pool.c and time.time() - tj >= JOB_S:
        njobs = getattr(pool, 'njobs', 0) + 1; pool.njobs = njobs
        pool.new_job(clean=(njobs % 3 == 0)); tj = time.time()   # 2 same-block jobs, then a new block
p.terminate()
try: p.wait(timeout=20)
except Exception: p.kill()
text = ''.join(out)
acc = sum(1 for e in pool.log if e[2]); rej = [e for e in pool.log if not e[2]]
print('\n=== pool log: %d shares, %d accepted, %d rejected: %s' % (len(pool.log), acc, len(rej), sorted(set(e[3] for e in rej))))
print('auth %s agent %s' % (pool.auth, pool.agent))
fails = []
if pool.auth != ('MSSADDRESS', 'simrig'): fails.append('auth')
if acc < 3: fails.append('too few accepted shares')
bad = [e for e in rej if e[3] not in ('stale job', 'Verifier busy, retry')]
if bad: fails.append('rejections other than stale/busy: %r' % bad[:5])
if 'WRONG hash' in text: fails.append('engine/reference mismatch reported')
print('accepted shares of an older same-block job: %d' % pool.old_ok)
if not WALK and getattr(pool, 'njobs', 0) >= 1 and pool.old_ok == 0: fails.append('no share of an older same-block job was submitted (work dropped?)')
if 'mds-cpu stopped' not in text and not WIN: fails.append('no clean exit')
if 'engine bug' in text: fails.append('kernel bug line')
if abs(text.count('share accepted') - acc) > 6: fails.append('miner counted %d accepted, pool %d' % (text.count('share accepted'), acc))
if 'verified' not in text and '--verbose' in cmd: fails.append('no CPU sample verification')
print('E2E RESULT:', 'ALL OK' if not fails else 'FAIL ' + '; '.join(fails))
sys.exit(1 if fails else 0)
