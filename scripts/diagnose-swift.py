import os, pathlib, shlex, subprocess, sys
out = pathlib.Path('/tmp/native-diagnostics')
out.mkdir(exist_ok=True)
log = (out / 'swift.log').open('w')
cmd = ['swift', 'test', '--package-path', 'macos/EsecVault'] + shlex.split(os.environ.get('TEST_ARGS', ''))
p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
try:
    code = p.wait(timeout=150)
except subprocess.TimeoutExpired:
    processes = subprocess.check_output(['ps', '-axo', 'pid,ppid,command'], text=True)
    (out / 'processes.txt').write_text(processes)
    print(processes)
    for line in processes.splitlines():
        if any(name in line for name in ['swiftpm-testing', 'EsecVaultPackageTests', 'swift-test']):
            pid = line.split()[0]
            subprocess.run(['sample', pid, '3', '-file', str(out / ('sample-' + pid + '.txt'))], timeout=15, check=False)
    os.killpg(p.pid, 15)
    code = 124
log.close()
print((out / 'swift.log').read_text())
for sample in out.glob('sample-*.txt'):
    print(sample.name)
    print(sample.read_text()[:40000])
sys.exit(code)
