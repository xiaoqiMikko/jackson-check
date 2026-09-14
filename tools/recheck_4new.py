# -*- coding: utf-8 -*-
r"""第 28 注(v0.2.0:08-21 / 09-01 新发 4 条)发文前事实复核 —— 退出码 0 = 全过。

跑:  python tools/recheck_4new.py

🔴 为什么另写一个,不扩 recheck_before_publish.py:那个脚本的独立口径是 OSV,
   而这 4 条在 OSV 上**恰恰没有 Maven 数据**(只有 Git 区间)—— 用它复核这 4 条等于没复核。
   所以本脚本换五个口径,且**不读 rules_dump.json / CveTable.java**:

A  官方仓库 advisory:4 条仍 published,严重度未变
B  GitHub 全局库:4 条按 GHSA 号仍 404(阳性:GHSA-5gvw-p9qm-jgwh 必须查得到)
C  OSV 按 Maven 坐标:2.21.5 查不出这 4 条(阳性:2.21.4 必须查出 GHSA-5gvw-p9qm-jgwh)
D  Central:修复版全 200(哨兵 2.21.999 = 404)
E  真 jar 字节码双向:补丁标记**只在修复版出现、前一版没有**
   19032 `_isSchemeAllowed` · 68497 `_validateTimestampLength` · 83557 `java/lang/Comparable`(2.21.5→2.21.6、3.1.5→3.1.6)
   77310 `InetAddressValidator`(2.21.4→2.21.5)
"""
import io
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
UA = {"User-Agent": "Mozilla/5.0"}
OLD = "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind"
NEW = "https://repo1.maven.org/maven2/tools/jackson/core/jackson-databind"
FOUR = {"GHSA-q4xh-88c3-wmh7": ("CVE-2026-68497", "high"),
        "GHSA-wjgm-6hv5-3cvf": ("CVE-2026-19032", "medium"),
        "GHSA-vvgp-rfg2-7rr6": ("CVE-2026-77310", "medium"),
        "GHSA-gx83-3vf8-gh7j": ("CVE-2026-83557", "medium")}
FAIL = []


def check(name, ok, detail=""):
    print(f"  {'✅' if ok else '❌'} {name}  {detail}")
    if not ok:
        FAIL.append(name)


def gh(path):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True, encoding="utf-8")
    return r.returncode, r.stdout, r.stderr


def http(url, data=None):
    req = urllib.request.Request(url, data=data, headers=dict(UA, **({"Content-Type": "application/json"} if data else {})),
                                 method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


print("A  官方仓库 advisory")
for g, (cve, sev) in FOUR.items():
    code, out, _ = gh(f"repos/FasterXML/jackson-databind/security-advisories/{g}")
    d = json.loads(out) if code == 0 else {}
    check(f"{g} published {cve} {sev}",
          d.get("state") == "published" and d.get("cve_id") == cve and d.get("severity") == sev,
          f"{d.get('state')} {d.get('cve_id')} {d.get('severity')}")

print("B  GitHub 全局库")
code, _, _ = gh("advisories/GHSA-5gvw-p9qm-jgwh")
check("阳性 GHSA-5gvw-p9qm-jgwh 查得到", code == 0)
for g in FOUR:
    code, out, err = gh(f"advisories/{g}")
    check(f"{g} 仍 404", code != 0 and "404" in out + err)

print("C  OSV 按 Maven 坐标")
def osv(v):
    body = json.dumps({"package": {"name": "com.fasterxml.jackson.core:jackson-databind", "ecosystem": "Maven"},
                       "version": v}).encode()
    st, b = http("https://api.osv.dev/v1/query", body)
    vulns = json.loads(b or b"{}").get("vulns", [])
    return st, {x["id"] for x in vulns} | {a for x in vulns for a in (x.get("aliases") or [])}
st, ids = osv("2.21.4")
check("阳性 2.21.4 查出 GHSA-5gvw-p9qm-jgwh", st == 200 and "GHSA-5gvw-p9qm-jgwh" in ids, str(len(ids)))
st, ids = osv("2.21.5")
leak = [x for g, (c, _) in FOUR.items() for x in (g, c) if x in ids]
check("2.21.5 查不出这 4 条", st == 200 and not leak, str(leak))

print("D  Central 修复版")
for base, v in [(OLD, "2.18.10"), (OLD, "2.21.6"), (OLD, "2.22.2"), (OLD, "2.22.1"), (NEW, "3.1.6"), (NEW, "3.2.2")]:
    st, _ = http(f"{base}/{v}/jackson-databind-{v}.pom")
    check(f"{v} = 200", st == 200, str(st))
st, _ = http(f"{OLD}/2.21.999/jackson-databind-2.21.999.pom")
check("哨兵 2.21.999 = 404", st == 404, str(st))

print("E  真 jar 字节码双向")
_cache = {}
def classes(base, v):
    if (base, v) not in _cache:
        st, b = http(f"{base}/{v}/jackson-databind-{v}.jar")
        z = zipfile.ZipFile(io.BytesIO(b))
        _cache[(base, v)] = [z.read(n) for n in z.namelist() if n.endswith(".class")]
    return _cache[(base, v)]
def has(base, v, marker):
    m = marker.encode()
    return any(m in c for c in classes(base, v))
for cve, marker, base, before, after in [
        ("19032", "_isSchemeAllowed", OLD, "2.21.5", "2.21.6"),
        ("68497", "_validateTimestampLength", OLD, "2.21.5", "2.21.6"),
        ("83557", "java/lang/Comparable", None, None, None),
        ("19032", "_isSchemeAllowed", NEW, "3.1.5", "3.1.6"),
        ("77310", "InetAddressValidator", OLD, "2.21.4", "2.21.5")]:
    if base is None:
        # Comparable 在别的类里本来就大量出现,只看拒绝列表那个类
        def ub(v):
            st, b = http(f"{OLD}/{v}/jackson-databind-{v}.jar")
            z = zipfile.ZipFile(io.BytesIO(b))
            n = "com/fasterxml/jackson/databind/jsontype/DefaultBaseTypeLimitingValidator$UnsafeBaseTypes.class"
            return b"java/lang/Comparable" in z.read(n)
        check("83557 UnsafeBaseTypes 含 java/lang/Comparable:2.21.6 有", ub("2.21.6"))
        check("83557 UnsafeBaseTypes 含 java/lang/Comparable:2.21.5 没有", not ub("2.21.5"))
        continue
    check(f"{cve} `{marker}`:{after} 有", has(base, after, marker))
    check(f"{cve} `{marker}`:{before} 没有", not has(base, before, marker))

print()
if FAIL:
    print(f"❌ {len(FAIL)} 项不过 —— 停下改文案:")
    for f in FAIL:
        print("   ·", f)
    sys.exit(1)
print("✅ 全过")
