# -*- coding: utf-8 -*-
r"""发文前事实复核 —— 用**独立口径**把文案里的承重数字再算一遍。

🔴 为什么不能复用 gen_rules.py 的结果:
   那样验的是「我抄没抄错自己的输出」,不是「这个数字对不对」。
   第 6 注 tomcat-check 的解析 bug 正是这么漏过所有检查的 ——
   错配的条目在每一项自洽性检查里都长得完全正常。

所以本脚本换一个数据库:**OSV(api.osv.dev)**,它是 Google 维护的独立聚合库,
和 gen_rules.py 用的 GitHub advisory API 是两套东西。
区间与修复版从 OSV 的 events 重新解析、交集重新计算,**不读 rules_dump.json**。

用法:python tools/recheck_before_publish.py [文案文件...]
     不带参数时只复核判定表本身;带文件时额外检查文案里出现的数字。
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
TABLE = os.path.join(HERE, "..", "src", "main", "java", "dev", "mikko", "jacksoncheck", "CveTable.java")

OLD_G = "com.fasterxml.jackson.core"
NEW_G = "tools.jackson.core"
ART = "jackson-databind"
CENTRAL = {OLD_G: "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/" + ART,
           NEW_G: "https://repo1.maven.org/maven2/tools/jackson/core/" + ART}

fails = []


def check(ok, msg):
    print(("  ✅ " if ok else "  🔴 ") + msg)
    if not ok:
        fails.append(msg)


def osv(coord):
    body = json.dumps({"package": {"name": coord, "ecosystem": "Maven"}}).encode()
    req = urllib.request.Request("https://api.osv.dev/v1/query", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        d = json.loads(urllib.request.urlopen(req, timeout=120).read())
    except Exception as e:
        sys.exit("🔴 OSV 拉取失败 %s:%s —— 拿不到 ≠ 没有条目,中止" % (coord, str(e)[:150]))
    return [v for v in d.get("vulns", []) if "2026" in (v.get("published") or "")]


def vkey(v):
    m = re.match(r"^(\d+(?:\.\d+)*)(?:[.\-]?(alpha|beta|rc|m)[.\-]?(\d*))?$", v or "", re.I)
    if not m:
        return (0,), 0, 0
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums += (0,) * (4 - len(nums))
    rank = {"alpha": 1, "beta": 2, "m": 1, "rc": 3}.get((m.group(2) or "").lower(), 9)
    return nums, rank, int(m.group(3) or 0)


def http_ok(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="HEAD")
        return urllib.request.urlopen(req, timeout=90).getcode() == 200
    except urllib.error.HTTPError:
        return False
    except Exception as e:
        sys.exit("🔴 探测失败 %s:%s" % (url, str(e)[:120]))


print("=" * 78)
print("发文前事实复核 —— 独立口径:OSV(api.osv.dev),不复用 gen_rules.py 的任何输出")
print("=" * 78)

# ── 1. 条目数 ──
print("\n[1] 条目数")
v_old, v_new = osv("%s:%s" % (OLD_G, ART)), osv("%s:%s" % (NEW_G, ART))
ids_old = {v["id"] for v in v_old}
ids_new = {v["id"] for v in v_new}
check(len(ids_old) == 11, "OSV 上旧坐标 2026 年条目 = %d(文案写 11)" % len(ids_old))
check(len(ids_new) == 9, "OSV 上新坐标 2026 年条目 = %d(文案写 9)" % len(ids_new))
check(ids_new <= ids_old, "新坐标的条目是旧坐标的子集(差的是 2.x 独有的那两条)")

# 判定表里的条目集合必须和 OSV 一致
src = open(TABLE, encoding="utf-8").read()
table_ghsa = set(re.findall(r'add\("(GHSA-[\w-]+)"', src))
check(table_ghsa == ids_old,
      "判定表条目集合与 OSV 完全一致(表 %d / OSV %d;只在表:%s;只在 OSV:%s)"
      % (len(table_ghsa), len(ids_old),
         sorted(table_ghsa - ids_old) or "无", sorted(ids_old - table_ghsa) or "无"))

# ── 2. 无 CVE 号的那条 ──
print("\n[2] 没有 CVE 号的条目(文案的承重论据)")
no_cve = [v["id"] for v in v_old if not any(a.startswith("CVE-") for a in (v.get("aliases") or []))]
check(no_cve == ["GHSA-mhm7-754m-9p8w"],
      "OSV 上唯一没有 CVE 号的是 %s" % (no_cve or "无 —— 承重论据失效!"))
check(no_cve and no_cve[0] not in ids_new,
      "它只挂旧坐标(3.x 线早修了,所以新坐标下没有)")

# ── 3. 逐分支交集,从 OSV 的 events 重新算 ──
print("\n[3] 逐分支求交集(从 OSV events 重算,不看 gen_rules 的结果)")
fixed_by = {}          # (坐标, 分支) → 该分支上所有修复版
for coord, vulns in ((OLD_G, v_old), (NEW_G, v_new)):
    for v in vulns:
        for aff in v.get("affected") or []:
            if (aff.get("package") or {}).get("name") != "%s:%s" % (coord, ART):
                continue
            for rng in aff.get("ranges") or []:
                for ev in rng.get("events") or []:
                    f = ev.get("fixed")
                    if not f:
                        continue
                    br = ".".join(f.split(".")[:2])
                    fixed_by.setdefault((coord, br), []).append((f, v["id"]))

EXPECTED = {(OLD_G, "2.18"): "2.18.9", (OLD_G, "2.21"): "2.21.5", (OLD_G, "2.22"): "2.22.1",
            (NEW_G, "3.1"): "3.1.5", (NEW_G, "3.2"): "3.2.1"}
for key, want in EXPECTED.items():
    got = fixed_by.get(key)
    if not got:
        check(False, "%s %s 线在 OSV 上一个修复版都没有 —— 表结构变了" % key)
        continue
    top = max(got, key=lambda t: vkey(t[0]))
    check(top[0] == want, "%-30s %-5s 线交集 = %s(文案写 %s),顶高它的是 %s"
          % (key[0], key[1], top[0], want, top[1]))

# ── 4. 「照单条 advisory 升级会漏」的那三条 ──
print("\n[4] 升到 2.21.4 仍然中的条目")
still = set()
for v in v_old:
    for aff in v.get("affected") or []:
        if (aff.get("package") or {}).get("name") != "%s:%s" % (OLD_G, ART):
            continue
        for rng in aff.get("ranges") or []:
            intro, fix = None, None
            for ev in rng.get("events") or []:
                intro = ev.get("introduced", intro)
                fix = ev.get("fixed", fix)
            if intro and fix and vkey(intro) <= vkey("2.21.4") < vkey(fix):
                still.add(v["id"])
want_still = {"GHSA-5jmj-h7xm-6q6v", "GHSA-5gvw-p9qm-jgwh", "GHSA-mhm7-754m-9p8w"}
check(still == want_still,
      "升到 2.21.4 仍中 %d 条:%s(文案写 3 条)" % (len(still), sorted(still)))

# ── 5. 双向幽灵坐标 ──
print("\n[5] 幽灵坐标(重新 HEAD 请求 Maven Central)")
check(not http_ok("%s/3.1.4/%s-3.1.4.jar" % (CENTRAL[OLD_G], ART)),
      "%s 的 3.1.4 拿不到(方向一)" % OLD_G)
check(not http_ok("%s/2.21.4/%s-2.21.4.jar" % (CENTRAL[NEW_G], ART)),
      "%s 的 2.21.4 拿不到(方向二)" % NEW_G)
check(http_ok("%s/3.1.4/%s-3.1.4.jar" % (CENTRAL[NEW_G], ART)),
      "对照组:%s 的 3.1.4 拿得到 —— 排除「Central 探测本身坏了」" % NEW_G)
check(http_ok("%s/2.21.4/%s-2.21.4.jar" % (CENTRAL[OLD_G], ART)),
      "对照组:%s 的 2.21.4 拿得到" % OLD_G)


def majors(group):
    xml = urllib.request.urlopen(urllib.request.Request(
        "%s/maven-metadata.xml" % CENTRAL[group],
        headers={"User-Agent": "Mozilla/5.0"}), timeout=90).read().decode("utf-8", "replace")
    return {v.split(".")[0] for v in re.findall(r"<version>([^<]+)</version>", xml)}


check(majors(OLD_G) == {"2"}, "%s 在 Central 上只发过 2.x(实际:%s)" % (OLD_G, sorted(majors(OLD_G))))
check(majors(NEW_G) == {"3"}, "%s 在 Central 上只发过 3.x(实际:%s)" % (NEW_G, sorted(majors(NEW_G))))

# ── 6. 文案里的数字 ──
for path in sys.argv[1:]:
    print("\n[6] 文案复核:%s" % path)
    if not os.path.exists(path):
        check(False, "文件不存在")
        continue
    text = open(path, encoding="utf-8").read()
    # 文案里出现的每个 CVE 编号都必须在判定表里
    cited = set(re.findall(r"CVE-2026-\d+", text))
    table_cve = set(re.findall(r'"(CVE-2026-\d+)"', src))
    check(cited <= table_cve, "文案引用的 CVE 全在判定表里(多出来的:%s)" % (sorted(cited - table_cve) or "无"))
    # 承重版本号必须原样出现,防手滑写成 2.21.4
    for want in ("2.18.9", "2.21.5", "3.1.5", "GHSA-mhm7-754m-9p8w"):
        check(want in text, "文案里出现了 %s" % want)
    # 🔴 口径红线:不许把「文件数」说成「项目数」
    bad = re.findall(r"只有\s*[\d.]+%\s*的项目", text)
    check(not bad, "没有把文件数说成项目数(命中:%s)" % (bad or "无"))

print("\n" + "=" * 78)
if fails:
    print("🔴 复核未通过,%d 项:" % len(fails))
    for f in fails:
        print("   - " + f)
    sys.exit(1)
print("✅ 全部复核项通过 —— 可以发")
