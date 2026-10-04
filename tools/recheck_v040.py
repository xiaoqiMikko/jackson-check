# -*- coding: utf-8 -*-
r"""v0.4.0 / 第 28、32 注更正块 —— 发文前复核(2026-10-05)。

要复核的是**更正块里的四句话**,口径故意不复用 gen_rules.py 的任何输出:

  A  「09-30 / 10-01 新发的 4 条都在 GitHub 全局库里」(所以**不许写成 Dependabot 不报**)
  B  「第 28 注那 4 条已被全局库收录」(原文『至今没收录』已过时)+ 收录日期
     「core 的 68498 仍查不到」(第 32 注的核心信息差**没塌**,更正时不许说过头)
  C  新的一次修完版本 2.18.11 / 2.21.7 / 2.22.3 / 3.1.7 / 3.2.3 在 Central 上都在(哨兵必须 404)
  D  ⭐ 真 jar 字节码**双向**:四条各取一个只在修复版里出现(或只在中招版里出现)的标记,
     2.21.6 ↔ 2.21.7、2.18.10 ↔ 2.18.11、3.1.6 ↔ 3.1.7 三条线都要复现。
     ☠️ 单向判据和没验证长得一模一样(第 23 注实证),所以每个标记都查两边。

退出码 0 = 全过;1 = 有不过的,**停下改文案**。
"""
import io
import json
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
GH = r"D:\Program Files\GitHub CLI\gh.exe"
FAIL = []


def ok(cond, label, detail=""):
    print("  %s %s  %s" % ("✅" if cond else "❌", label, detail))
    if not cond:
        FAIL.append(label)


def gh_adv(query):
    r = subprocess.run([GH, "api", query], capture_output=True, text=True, encoding="utf-8", timeout=180)
    if r.returncode == 0:
        return json.loads(r.stdout)
    if "404" in (r.stdout or "") + (r.stderr or ""):
        return None
    sys.exit("🔴 查询 %s 失败且不是 404:%s —— 拿不到 ≠ 不存在,中止" % (query, (r.stderr or "")[:200]))


def http_code(url):
    req = urllib.request.Request(url, method="HEAD")
    try:
        return urllib.request.urlopen(req, timeout=60).status
    except urllib.error.HTTPError as e:
        return e.code


def jar_class(group_path, art, ver, cls):
    url = "https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar" % (group_path, art, ver, art, ver)
    data = urllib.request.urlopen(url, timeout=180).read()
    return zipfile.ZipFile(io.BytesIO(data)).read(cls)


# ───────────────────────── A:新 4 条在全局库里 ─────────────────────────
print("A  09-30 / 10-01 新发 4 条:GitHub 全局库")
NEW4 = {"CVE-2026-91776": "jackson-databind", "CVE-2026-91777": "jackson-databind",
        "CVE-2026-89425": "jackson-core", "CVE-2026-89407": "jackson-core"}
sent = gh_adv("advisories?cve_id=CVE-1999-99999")
ok(sent == [], "哨兵 CVE-1999-99999 返回空", "返回 %s 条" % (len(sent) if sent is not None else "404"))
for cve, art in NEW4.items():
    arr = gh_adv("advisories?cve_id=" + cve) or []
    a = arr[0] if arr else {}
    pk = sorted({(v.get("package") or {}).get("name", "") for v in a.get("vulnerabilities") or []})
    ok(bool(arr) and a.get("type") == "reviewed" and a.get("severity") == "high"
       and not a.get("withdrawn_at") and all(p.endswith(":" + art) for p in pk) and len(pk) == 2,
       "%s 已收录 · reviewed · high · 挂在 %s 两个 groupId 上" % (cve, art),
       "published %s" % (a.get("published_at") or "")[:10])

# ───────────────────────── B:旧主张的现状 ─────────────────────────
print("B  旧主张现状")
OLD4 = ["GHSA-q4xh-88c3-wmh7", "GHSA-wjgm-6hv5-3cvf", "GHSA-vvgp-rfg2-7rr6", "GHSA-gx83-3vf8-gh7j"]
for g in OLD4:
    a = gh_adv("advisories/" + g)
    ok(a is not None and a.get("type") == "reviewed",
       "第 28 注 %s 现已被全局库收录" % g,
       "全局库 published %s" % ((a or {}).get("published_at") or "")[:10])
a68498 = gh_adv("advisories/GHSA-649p-m576-vr99")
ok(a68498 is None, "第 32 注 CVE-2026-68498(GHSA-649p-m576-vr99)仍 404 —— 核心信息差没塌")

# ───────────────────────── C:修复版在 Central ─────────────────────────
print("C  Central 修复版")
P2 = "com/fasterxml/jackson/core"
P3 = "tools/jackson/core"
for art in ("jackson-databind", "jackson-core"):
    for gp, vers in ((P2, ("2.18.11", "2.21.7", "2.22.3")), (P3, ("3.1.7", "3.2.3"))):
        for v in vers:
            code = http_code("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar" % (gp, art, v, art, v))
            ok(code == 200, "%s %s = 200" % (art, v), str(code))
code = http_code("https://repo1.maven.org/maven2/%s/jackson-databind/2.21.999/jackson-databind-2.21.999.jar" % P2)
ok(code == 404, "哨兵 2.21.999 = 404", str(code))

# ───────────────────────── D:字节码双向 ─────────────────────────
print("D  真 jar 字节码双向(中招版 ↔ 修复版)")
# (CVE, artifact, class, 标记, 修复版里应该有吗)
MARKS = [
    ("CVE-2026-91776", "jackson-databind", "{pkg}/databind/jsontype/impl/TypeDeserializerBase.class",
     b"MAX_CACHED_TYPE_IDS", True),
    ("CVE-2026-91777", "jackson-databind",
     "{pkg}/databind/deser/{sub}/CollectionDeserializer$CollectionReferringAccumulator.class",
     b"_unresolvedById", True),
    ("CVE-2026-89425", "jackson-core", "{pkg}/core/json/UTF8DataInputJsonParser.class",
     b"getMaxErrorTokenLength", True),
    # 这一条方向相反:修复 = 把那两个正则删掉
    ("CVE-2026-89407", "jackson-core", "{pkg}/core/io/NumberInput.class", b"PATTERN_FLOAT", False),
]
# 🔴 3.x 把集合反序列化器从 deser/std 挪到了 deser/jdk —— 首跑时照 2.x 的路径去找,
#    报的是「类不存在」而不是「标记不在」。两种失败必须分开报,否则会被读成「3.x 没修」。
LINES = [(P2, "com/fasterxml/jackson", "std", "2.21.6", "2.21.7"),
         (P2, "com/fasterxml/jackson", "std", "2.18.10", "2.18.11"),
         (P3, "tools/jackson", "jdk", "3.1.6", "3.1.7")]
for gp, pkg, sub, bad, good in LINES:
    for cve, art, cls, mark, in_fixed in MARKS:
        c = cls.format(pkg=pkg, sub=sub)
        try:
            b_bad = jar_class(gp, art, bad, c)
            b_good = jar_class(gp, art, good, c)
        except KeyError as e:
            ok(False, "%s %s→%s 类不存在" % (cve, bad, good), str(e)[:80])
            continue
        has_bad, has_good = mark in b_bad, mark in b_good
        ok(has_good == in_fixed and has_bad != in_fixed,
           "%s `%s`:%s %s / %s %s" % (cve, mark.decode(), bad, "有" if has_bad else "无",
                                     good, "有" if has_good else "无"))

print()
if FAIL:
    print("❌ %d 项不过 —— 停下改文案:" % len(FAIL))
    for f in FAIL:
        print("   · " + f)
    sys.exit(1)
print("✅ 全过,可以发")
