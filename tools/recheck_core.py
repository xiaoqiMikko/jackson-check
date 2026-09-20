# -*- coding: utf-8 -*-
"""第 32 注(jackson-core)发文前复核 —— 退出码 0=通过,3=信息差变了文案要改。

🔴 **为什么它在仓库里而不在 scratchpad**:2026-09-21 找弹药时发现上一轮的 `repo_gap.py`
   随会话被清掉了,而那是唯一一份实现。**临时目录里的脚本等于没有这个脚本。**

🔴 **口径故意不复用 gen_rules.py 的任何输出**:这里独立走 NVD 与 Maven Central,
   连 advisory 都重新拉一次。复核脚本唯一不可替代的价值,就是用**另一个口径**把同一批东西数一遍
   (第 6 注实证:7 条断言 + 34 个测试 + 4 个真 jar 复验全过,而复核抓出一条 CVE 挂着别人的标题)。
"""
import subprocess, json, sys, io, os, urllib.request, zipfile, tempfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace",
                              line_buffering=True)
GH = os.environ.get("GH_BIN", r"D:\Program Files\GitHub CLI\gh.exe")
CORE_REPO = "FasterXML/jackson-core"
TARGET = "CVE-2026-68498"
TARGET_GHSA = "GHSA-649p-m576-vr99"
ok = True


def say(tag, good, msg=""):
    global ok
    print(f"  {'✅' if good else '🔴'} {tag}{('  ' + msg) if msg else ''}")
    if not good:
        ok = False


def gh(path):
    r = subprocess.run([GH, "api", path], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=180)
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except Exception:
        return None


def http_code(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="HEAD")
        return urllib.request.urlopen(req, timeout=90).getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        sys.exit("🔴 探测失败 %s:%s —— 拿不到 ≠ 不存在,中止" % (url, str(e)[:120]))


print("=" * 74)
print("A 组:核心信息差 —— 全局库仍查不到 68498(裸 0 不算数,必须有阳性对照)")
a = gh("advisories?cve_id=" + TARGET)
pos = gh("advisories?cve_id=CVE-2026-29062")     # 同仓库、已收录的一条
say("A1 阳性对照 CVE-2026-29062 查得到", bool(pos), f"返回 {0 if pos is None else len(pos)} 条")
say("A2 68498 仍未被全局库收录", a is not None and len(a) == 0,
    "仍 404" if a == [] else "🔴 已被收录 → 文案「Dependabot 报不出这一条」要改写")

print()
print("B 组:口径红线 —— core 那批里**只有这一条**是盲区(说过头会被一查就抓)")
adv = gh("/repos/%s/security-advisories?per_page=100" % CORE_REPO) or []
pub = [x for x in adv if x.get("state") == "published"]
say("B1 公告总数 ≥ 7", len(pub) >= 7, f"实读 {len(pub)} 条")
blind = []
for x in pub:
    g = x["ghsa_id"]
    r = subprocess.run([GH, "api", "/advisories/" + g], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=180)
    if r.returncode != 0 and "404" in (r.stdout or "") + (r.stderr or ""):
        blind.append(g)
say("B2 盲区正好 1 条且就是 68498", blind == [TARGET_GHSA],
    f"实读 {blind}" + ("" if blind == [TARGET_GHSA] else "  🔴 信息差变了,文案必须改"))

print()
print("C 组:五个修复版仍在 Central 上(印一个装不上的版本 = 让人做一件做不成的事)")
C2 = "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core"
C3 = "https://repo1.maven.org/maven2/tools/jackson/core/jackson-core"
for base, v in [(C2, "2.18.10"), (C2, "2.21.6"), (C2, "2.22.2"), (C3, "3.1.6"), (C3, "3.2.2")]:
    say(f"C {v}", http_code(f"{base}/{v}/jackson-core-{v}.jar") == 200)
say("C 阳性对照 2.21.5(中招版,必须在)", http_code(f"{C2}/2.21.5/jackson-core-2.21.5.jar") == 200)
say("C 哨兵 2.21.999(必须 404)", http_code(f"{C2}/2.21.999/jackson-core-2.21.999.jar") == 404)

print()
print("D 组:真 jar 字节码**双向** —— 修复版有 validateNameLength,中招版必须没有")
print("     ☠️ 单向判据和没验证长得一模一样(第 23 注实证)")
NEEDLE = b"validateNameLength"
CASES = [(C2, "2.21.5", "2.21.6", "com/fasterxml/jackson/core"),
         (C2, "2.18.9", "2.18.10", "com/fasterxml/jackson/core"),
         (C3, "3.1.5", "3.1.6", "tools/jackson/core")]
tmp = tempfile.gettempdir()
for base, old, new, pkg in CASES:
    hits = {}
    for v in (old, new):
        fn = os.path.join(tmp, f"recheck-jackson-core-{v}.jar")
        if not os.path.exists(fn):
            urllib.request.urlretrieve(f"{base}/{v}/jackson-core-{v}.jar", fn)
        z = zipfile.ZipFile(fn)
        # ☠️ 坏 jar 会安静地给 0 条目(㉙)—— 先证明它真读进去了
        if len(z.namelist()) < 50:
            sys.exit(f"🔴 {fn} 只有 {len(z.namelist())} 个条目 —— 读作「读不动」,不是「空」")
        hits[v] = NEEDLE in z.read(pkg + "/json/ReaderBasedJsonParser.class")
    say(f"D {old} 无 / {new} 有", (not hits[old]) and hits[new],
        f"旧={'有' if hits[old] else '无'} 新={'有' if hits[new] else '无'}")

print()
print("=" * 74)
print("复核结论:" + ("✅ 全过,可以发" if ok else "🔴 有不过的 —— 停下改文案,别先发"))
sys.exit(0 if ok else 3)
