# -*- coding: utf-8 -*-
r"""从**两个一手源**生成 CveTable.java + Triggers.java —— 一行都不手抄。

源 A:GitHub 仓库级 advisory   /repos/FasterXML/jackson-databind/security-advisories
      = 维护者自己发布的**条目全集** + 描述原文 + 触发条件原文
源 B:GitHub 全局 advisory DB  /advisories?ecosystem=maven&affects=<坐标>
      = **Dependabot 实际用的坐标索引**(两个 groupId 各查一次)

🔴 两个源必须都查,这是第 8 注最贵的教训:
   「有没有 Dependabot 盲区」这个判断本身就得用两个源 ——
   单源得出的「没有盲区」和「真的没有」长得一模一样。
   本注查完的诚实结论是**没有盲区**(与第 8 注相反),ASSERT2 每次重跑都会重新核实。

🔴 本脚本存在的理由,是三个只有把两个源摆在一起、并去 Maven Central 实测才看得见的事实:

   1. **照单条 advisory 升级会漏。** 8 条 advisory 反复给出 2.21.4 / 2.18.8 / 3.1.4,
      而 GHSA-mhm7-754m-9p8w 原文明写「the fix was never backported to 2.21 or 2.18 …
      Users on 2.21.4 and 2.18.8 who upgraded per the published advisories remain vulnerable」。
      逐条求交集后真正的答案是 2.18.9 / 2.21.5 / 2.22.1 / 3.1.5 / 3.2.1。ASSERT9 钉死这个差。

   2. **两个 groupId 被交叉贴错了版本区间。** Jackson 3 换了 groupId
      (com.fasterxml.jackson.core → tools.jackson.core),而 advisory 里
      旧坐标挂着 3.x 区间、新坐标挂着 2.x 区间,**两边在 Central 上都是 404**。
      照抄 advisory 的工具会让人去装一个不存在的东西。ASSERT7/ASSERT8 逐个实测。

   3. **11 条的触发条件在源码注解里,能自动扫。** 多数条目只在用了
      @JsonView / 多态类型 / 大小写不敏感 等特性的代码里成立 ——
      Dependabot 只看版本会把 11 条全报。ASSERT10/ASSERT11 保证降噪表不是我编的。

任一断言不满足 → **中止,不写文件**(防「解析失败生成空壳表而测试照样全绿」)。
"""
import io
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
GH = r"D:\Program Files\GitHub CLI\gh.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "src", "main", "java", "dev", "mikko", "jacksoncheck")

REPO = "FasterXML/jackson-databind"
OLD_G = "com.fasterxml.jackson.core"      # Jackson 2.x
NEW_G = "tools.jackson.core"              # Jackson 3.x —— 换了 groupId
ART = "jackson-databind"
CENTRAL = {OLD_G: "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/" + ART,
           NEW_G: "https://repo1.maven.org/maven2/tools/jackson/core/" + ART}

# 只做 2026 年这一批。更早的条目属于「历史反序列化 gadget」那条老线,搜索生态与工具形态都不同。
BATCH_YEAR = "2026"

# ────────────────────────── 唯一的人工输入(降噪表)──────────────────────────
#
# 🔴 这张表是本脚本仅有的人工内容,所以每一条都配了断言:
#    ANCHOR 里的字符串必须**逐字出现在该条 advisory 的描述原文里**(ASSERT11)。
#    「我记得这条是 @JsonView 的」不算依据 —— 官方原文里有这个词才算。
#
# 格式:GHSA → (触发条件分类, 中文说明, [源码标记...], [原文锚点串...])
#
# 「源码标记」是 SourceScan 在 .java 文本里找的东西。全部命中 = 条件成立;
# 部分命中 = 可能成立;一个都不命中 = 报告里标为「未在你的源码里找到触发条件」,
# 🔴 **并且必须同时印出「这不等于安全」** —— 传递依赖里的库也可能用这些注解,而我们扫不到它的源码。
CONDITIONS = {
    "GHSA-j3rv-43j4-c7qm": (
        "POLYMORPHIC",
        "仅当开启了多态类型(@JsonTypeInfo 或 activateDefaultTyping)且配置了 PolymorphicTypeValidator,"
        "并且攻击者能控制 type id 字符串",
        ["@JsonTypeInfo", "PolymorphicTypeValidator"],
        ["PolymorphicTypeValidator", "polymorphic typing is enabled"]),
    "GHSA-rmj7-2vxq-3g9f": (
        "POLYMORPHIC_ARRAY",
        "仅当用 BasicPolymorphicTypeValidator 且调用了 allowIfSubTypeIsArray() 来放行数组类型",
        ["PolymorphicTypeValidator", "allowIfSubTypeIsArray"],
        ["allowIfSubTypeIsArray", "BasicPolymorphicTypeValidator"]),
    "GHSA-hgj6-7826-r7m5": (
        "INET_SOCKET_ADDRESS",
        "仅当把不可信 JSON 绑定到含 InetSocketAddress 字段的类型上(绑定时就会发起 DNS 查询)",
        ["InetSocketAddress"],
        ["InetSocketAddress"]),
    "GHSA-5jmj-h7xm-6q6v": (
        "CASE_INSENSITIVE",
        "仅当同时开启了大小写不敏感匹配(@JsonFormat 的 ACCEPT_CASE_INSENSITIVE_PROPERTIES)"
        "并依赖逐属性的 @JsonIgnoreProperties 把字段挡在外面",
        ["ACCEPT_CASE_INSENSITIVE_PROPERTIES", "@JsonIgnoreProperties"],
        ["ACCEPT_CASE_INSENSITIVE_PROPERTIES", "@JsonIgnoreProperties"]),
    "GHSA-9fxm-vc8v-hj55": (
        "IGNORED_SETTER_RENAME",
        "仅当同一个属性上 getter 带 @JsonProperty 改了名、setter 带 @JsonIgnore"
        "(即「只读不写」的写法)",
        ["@JsonIgnore", "@JsonProperty"],
        ["@JsonProperty(\"renamed\")", "@JsonIgnore"]),
    "GHSA-5hh8-q8hv-fr38": (
        "JSONVIEW",
        "仅当用 @JsonView 做写入侧权限门控,且被门控的是 setterless 的 Collection/Map 属性",
        ["@JsonView"],
        ["@JsonView", "setterless"]),
    "GHSA-rcqc-6cw3-h962": (
        "JSONVIEW_UNWRAPPED",
        "仅当 @JsonView 与 @JsonUnwrapped 同时标在构造器(creator)参数上",
        ["@JsonView", "@JsonUnwrapped"],
        ["@JsonView", "@JsonUnwrapped"]),
    "GHSA-3pjw-73gf-8qr5": (
        "RECORD_NAMING",
        "仅当用 Java Record + PropertyNamingStrategy(命名策略),且靠 @JsonIgnore 挡住某个组件",
        ["record", "PropertyNamingStrategy", "@JsonIgnore"],
        ["PropertyNamingStrategy", "@JsonIgnore", "Record"]),
    "GHSA-5gvw-p9qm-jgwh": (
        "JSONVIEW_UNWRAPPED",
        "仅当同一个属性上同时有 @JsonView 和 @JsonUnwrapped(容器属性,非构造器参数)",
        ["@JsonView", "@JsonUnwrapped"],
        ["@JsonView", "@JsonUnwrapped"]),
    "GHSA-mhm7-754m-9p8w": (
        "JSONVIEW_EXTERNAL_TYPEID",
        "仅当构造器参数上同时有 @JsonView 和 @JsonTypeInfo(include = As.EXTERNAL_PROPERTY)",
        ["@JsonView", "@JsonTypeInfo", "EXTERNAL_PROPERTY"],
        ["EXTERNAL_PROPERTY", "@JsonView"]),
    "GHSA-3wrr-7qpf-2prh": (
        "JSONNODE_TOSTRING",
        "仅当用 ObjectMapper.readTree() 读入深层嵌套 JSON,再用 JsonNode.toString() 输出",
        ["readTree", "JsonNode"],
        ["readTree", "toString()"]),
}

# 源码标记 → (正则, 中文名)。
# 🔴 `@JsonIgnore` 必须排除 `@JsonIgnoreProperties` / `@JsonIgnoreType`,
#    否则任何用了 @JsonIgnoreProperties 的项目都会被判成中了 IGNORED_SETTER_RENAME。
#    这类前缀吞并是文本匹配最典型的误报来源,单独写进测试。
MARKERS = {
    "@JsonView": (r"@JsonView\b", "@JsonView 注解"),
    "@JsonUnwrapped": (r"@JsonUnwrapped\b", "@JsonUnwrapped 注解"),
    "@JsonTypeInfo": (r"@JsonTypeInfo\b", "@JsonTypeInfo 注解(多态类型)"),
    "@JsonIgnore": (r"@JsonIgnore(?![A-Za-z])", "@JsonIgnore 注解(不含 @JsonIgnoreProperties)"),
    "@JsonIgnoreProperties": (r"@JsonIgnoreProperties\b", "@JsonIgnoreProperties 注解"),
    "@JsonProperty": (r"@JsonProperty\b", "@JsonProperty 注解"),
    "PolymorphicTypeValidator": (r"\bPolymorphicTypeValidator\b|\bactivateDefaultTyping\b",
                                 "PolymorphicTypeValidator / activateDefaultTyping"),
    "allowIfSubTypeIsArray": (r"\ballowIfSubTypeIsArray\b", "allowIfSubTypeIsArray()"),
    "ACCEPT_CASE_INSENSITIVE_PROPERTIES": (r"\bACCEPT_CASE_INSENSITIVE_PROPERTIES\b",
                                           "ACCEPT_CASE_INSENSITIVE_PROPERTIES"),
    "InetSocketAddress": (r"\bInetSocketAddress\b", "InetSocketAddress 类型"),
    "PropertyNamingStrategy": (r"\bPropertyNamingStrategy\b|@JsonNaming\b",
                               "PropertyNamingStrategy / @JsonNaming"),
    "EXTERNAL_PROPERTY": (r"\bEXTERNAL_PROPERTY\b", "As.EXTERNAL_PROPERTY"),
    "readTree": (r"\breadTree\s*\(", "ObjectMapper.readTree()"),
    "JsonNode": (r"\bJsonNode\b", "JsonNode 类型"),
    # Java Record 声明。要求后面跟标识符和 '(',否则 "record" 作为普通变量名会误命中。
    "record": (r"\brecord\s+[A-Z]\w*\s*\(", "Java Record 声明"),
}

# 用来判断「这份源码到底用没用 jackson」的上锚。一个标记都没命中时,
# 靠它区分两种完全不同的情况:没用 jackson(合理) vs 用了但没用到这些特性(才是降噪)。
ANCHOR_MARKER = "ObjectMapper"
MARKERS[ANCHOR_MARKER] = (r"\bObjectMapper\b", "ObjectMapper(是否用到 jackson 的上锚)")


def gh(path):
    r = subprocess.run([GH, "api", path], capture_output=True, text=True,
                       encoding="utf-8", timeout=180)
    if r.returncode != 0:
        sys.exit("🔴 GitHub API 失败(%s):%s —— 拿不到 ≠ 没有,中止" % (path, (r.stderr or "")[:250]))
    return json.loads(r.stdout)


def in_batch(adv):
    """本批 = 2026 年那 11 条。含一条没有 CVE 号的,不能只按 cve_id 过滤。"""
    cve = adv.get("cve_id") or ""
    if cve.startswith("CVE-%s-" % BATCH_YEAR):
        return True
    # 没有 CVE 号的条目按发布时间归批
    return not cve and (adv.get("published_at") or "").startswith(BATCH_YEAR)


# ────────────────────────── 源 A:官方仓库 advisory ──────────────────────────
srcA_all = gh("/repos/%s/security-advisories?per_page=100" % REPO)
official = {a["ghsa_id"]: a for a in srcA_all if a.get("state") == "published" and in_batch(a)}
order = sorted(official, key=lambda g: (official[g].get("cve_id") or "zzz", g))

print("源 A(官方仓库 advisory):%s 年这批 %d 条" % (BATCH_YEAR, len(official)))

# ASSERT1:必须解析出足够多的条目,否则是 API 形状变了而不是「jackson 很太平」
assert len(official) >= 10, "🔴 ASSERT1 失败:官方只拿到 %d 条,API 形状可能已变" % len(official)

# ASSERT3:描述原文不能为空 —— 空描述会让报告里那一条看起来「没什么事」,
#          而触发条件全部来自描述原文,它空了降噪就是编的
thin = [g for g in official if len(official[g].get("description") or "") < 200]
assert not thin, "🔴 ASSERT3 失败:这些条目没拿到描述原文:%s" % thin


# ────────────── 源 B:按坐标反查(Dependabot 实际用的索引)──────────────
def by_coord(group):
    arr = gh("/advisories?ecosystem=maven&affects=%s:%s&per_page=100" % (group, ART))
    return {a["ghsa_id"]: a for a in arr if in_batch(a)}

srcB = {g: by_coord(g) for g in (OLD_G, NEW_G)}
print("源 B(按坐标反查,Dependabot 索引):")
for g in (OLD_G, NEW_G):
    print("   %-30s %d 条" % (g, len(srcB[g])))

# ASSERT2 ⭐ 双源盲区对比 —— 第 8 注最贵的教训:这个判断本身就必须用两个源
#
# 🔴 差值 = 官方发布了、但按坐标查不到的条目。它们进不了 Dependabot 告警。
#    第 8 注 shiro 一比出来 5 条;本注一比出来 0 条 —— **结论相反,但方法相同**。
#    ASSERT2 不锁定结论,只要求「差值必须被逐条解释」:
#    要么这条对该坐标本就不适用(官方没给它挂这个坐标),要么就是真盲区,必须停下来。
union_b = set(srcB[OLD_G]) | set(srcB[NEW_G])
blind = sorted(set(official) - union_b)
print("\nASSERT2 盲区对比:官方 %d 条 · 两个坐标反查合计 %d 条 · 差值 %d 条"
      % (len(official), len(union_b), len(blind)))
assert not blind, (
    "🔴 ASSERT2 失败:这 %d 条官方发布了但按两个坐标都查不到 —— 它们进不了 Dependabot 告警,"
    "是真盲区,必须写进报告和文案:%s" % (len(blind), blind))
extra_b = sorted(union_b - set(official))
assert not extra_b, (
    "🔴 ASSERT2 反向失败:这些条目按坐标查得到,官方仓库页面上却没有 —— "
    "说明「官方页面是全集」这个前提不成立:%s" % extra_b)
# 各坐标各自缺了哪些(不是盲区,但要打印出来供人核对「缺的那条确实与该坐标无关」)
for g in (OLD_G, NEW_G):
    miss = sorted(set(official) - set(srcB[g]))
    if miss:
        print("   %-30s 少 %d 条:%s" % (g, len(miss), ", ".join(
            "%s(%s)" % (m, official[m].get("cve_id") or "无CVE号") for m in miss)))
print("   → 差值为 0:本注**没有** Dependabot 盲区。这是查了两个源之后的结论,不是只查一个源的默认值。")


# ────────────────────────── 版本区间解析 ──────────────────────────
RANGE_RE = re.compile(r"^\s*(>=|<=|<|>|=)\s*(\S+)\s*$")


def parse_range(s):
    """把 '>= 2.10.0, <= 2.18.7' 拆成 (low, lowIncl, high, highIncl)。

    🔴 端点开闭**照抄不换算**:第 6 注在「官方闭区间 ↔ GitHub first_patched」之间
       做换算时错位过一格,而错位一格的判定表看起来完全正常。少一次换算 = 少一处静默出错点。
    """
    low = high = ""
    low_incl = high_incl = False
    for part in s.split(","):
        m = RANGE_RE.match(part)
        if not m:
            sys.exit("🔴 无法解析版本区间片段 %r(整段 %r)—— 解析不了就不能猜,中止" % (part, s))
        op, ver = m.group(1), m.group(2)
        if op == "=":
            return ver, True, ver, True
        if op == ">=":
            low, low_incl = ver, True
        elif op == ">":
            low, low_incl = ver, False
        elif op == "<=":
            high, high_incl = ver, True
        elif op == "<":
            high, high_incl = ver, False
    return low, low_incl, high, high_incl


def branch(version):
    """2.18.9 → '2.18';3.1.5 → '3.1'。用于「你这条维护分支上的答案是什么」。"""
    m = re.match(r"^(\d+)\.(\d+)", version or "")
    return "%s.%s" % (m.group(1), m.group(2)) if m else "?"


print("\n展开成「advisory × 坐标 × 区间」规则...")
rows = []
for ghsa in order:
    a = official[ghsa]
    # 受影响坐标只能取自源 B(官方仓库端点的 vulnerabilities 同样有,但源 B 才是 Dependabot 用的那份)
    vulns = []
    for g in (OLD_G, NEW_G):
        if ghsa in srcB[g]:
            for v in srcB[g][ghsa].get("vulnerabilities") or []:
                name = (v.get("package") or {}).get("name") or ""
                if name in ("%s:%s" % (OLD_G, ART), "%s:%s" % (NEW_G, ART)):
                    vulns.append(v)
    # 同一条 advisory 在两个坐标下都查得到时会重复,按 (坐标, 区间) 去重
    seen = set()
    for v in vulns:
        grp = (v.get("package") or {}).get("name").split(":")[0]
        rng = v.get("vulnerable_version_range") or ""
        key = (grp, rng)
        if key in seen:
            continue
        seen.add(key)
        low, li, high, hi = parse_range(rng)
        fixed = v.get("first_patched_version") or ""
        rows.append({"ghsa": ghsa, "group": grp, "low": low, "low_incl": li,
                     "high": high, "high_incl": hi, "fixed": fixed, "branch": branch(fixed)})

# ASSERT4:每条 advisory 都必须落成至少一条规则 —— 防止某条被静默丢掉
lost = [g for g in official if not any(r["ghsa"] == g for r in rows)]
assert not lost, "🔴 ASSERT4 失败:这些条目一条规则都没生成:%s" % lost

# ASSERT5:触发条件必须每条都有(留空会被读者读成「无条件即中招」)
missing = [g for g in official if g not in CONDITIONS]
assert not missing, "🔴 ASSERT5 失败:这些条目缺触发条件标注:%s" % missing
extra = [g for g in CONDITIONS if g not in official]
assert not extra, "🔴 ASSERT5 失败:CONDITIONS 里有官方已不存在的条目(该删):%s" % extra

# ASSERT6 ⭐ 两个 groupId 都必须覆盖到 —— Jackson 3 换了 groupId,
#           只做旧坐标的工具对 3.x 用户完全无效,而它看起来「跑得好好的」
by_group = {}
for r in rows:
    by_group.setdefault(r["group"], []).append(r)
for g in (OLD_G, NEW_G):
    assert len(by_group.get(g, [])) >= 3, (
        "🔴 ASSERT6 失败:%s 只有 %d 条规则 —— 两个 groupId 必须都覆盖" % (g, len(by_group.get(g, []))))
print("ASSERT6 双 groupId:%s %d 条 · %s %d 条 ✅"
      % (OLD_G, len(by_group[OLD_G]), NEW_G, len(by_group[NEW_G])))


# ─────────── ASSERT7 ⭐ 每个修复版都必须真的能升上去(第 8 注 ASSERT12 复用)───────────
#
# 🔴 由来:advisory 的 first_patched_version 里有两类坑,含义完全不同:
#      (a) **写法差异** —— 构件是有的,只是版本串对不上 → 规范化后照常用。
#      (b) **真的没发布** —— 照它去升是升不动的 → 必须标出来,让报告改口。
#    把一个升不了的版本印成升级建议,不是「误报」,是让用户去做一件做不成的事。
#    本注的 (b) 特别多,因为 Jackson 3 换了 groupId 而 advisory 两边贴串了。
print("\nASSERT7:逐个探测修复版本在 Maven Central 上拿不拿得到...", flush=True)


def http_code(url, method="HEAD"):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method=method)
        return urllib.request.urlopen(req, timeout=90).getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        sys.exit("🔴 ASSERT7 探测失败 %s:%s —— 拿不到 ≠ 版本不存在,中止" % (url, str(e)[:120]))


_probe = {}
for r in rows:
    if not r["fixed"]:
        r["fixed_ok"] = False
        continue
    key = (r["group"], r["fixed"])
    if key not in _probe:
        url = "%s/%s/%s-%s.jar" % (CENTRAL[r["group"]], r["fixed"], ART, r["fixed"])
        code = http_code(url)
        _probe[key] = code == 200
        print("   %s %-30s %-10s HTTP %s" % ("  " if code == 200 else "🔴", key[0], key[1], code))
    r["fixed_ok"] = _probe[key]

ghosts = sorted(k for k, ok in _probe.items() if not ok)
assert ghosts, (
    "🔴 ASSERT7 失败:一个拿不到的修复版都没有 —— 「幽灵坐标」这个核心主张不再成立,文案要改")
assert len(ghosts) <= len(_probe) * 0.5, (
    "🔴 ASSERT7 失败:%d/%d 个修复版都拿不到,探测逻辑八成坏了" % (len(ghosts), len(_probe)))
print("   共 %d 个不同的修复版,其中 %d 个在 Central 上拿不到 ✅" % (len(_probe), len(ghosts)))

# ASSERT8 ⭐ 幽灵是**双向**的:旧坐标上挂着 3.x、新坐标上挂着 2.x
#
# 只证明「某个版本 404」还不够 —— 那可能只是发布延迟。必须证明**整条大版本线**
# 在那个坐标下根本不存在,才能说 advisory 把两个 groupId 贴串了。
# 判据:去 Central 拉 maven-metadata.xml,看该坐标发布过哪些 major。
def majors(group):
    url = "%s/maven-metadata.xml" % CENTRAL[group]
    try:
        xml = urllib.request.urlopen(urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0"}), timeout=90).read().decode("utf-8", "replace")
    except Exception as e:
        sys.exit("🔴 ASSERT8 拉 maven-metadata 失败 %s:%s" % (url, str(e)[:120]))
    return {v.split(".")[0] for v in re.findall(r"<version>([^<]+)</version>", xml)}


maj = {g: majors(g) for g in (OLD_G, NEW_G)}
print("\nASSERT8 双向幽灵:")
print("   %-30s Central 上发布过的大版本:%s" % (OLD_G, ",".join(sorted(maj[OLD_G]))))
print("   %-30s Central 上发布过的大版本:%s" % (NEW_G, ",".join(sorted(maj[NEW_G]))))
assert "3" not in maj[OLD_G], "🔴 ASSERT8 失败:旧 groupId 上出现了 3.x,「幽灵坐标」论据不成立"
assert "2" not in maj[NEW_G], "🔴 ASSERT8 失败:新 groupId 上出现了 2.x,「幽灵坐标」论据不成立"

ghost_old3 = [r for r in rows if r["group"] == OLD_G and r["branch"].startswith("3.")]
ghost_new2 = [r for r in rows if r["group"] == NEW_G and r["branch"].startswith("2.")]
assert ghost_old3, "🔴 ASSERT8 失败:旧 groupId 上没有 3.x 区间,方向一的幽灵不存在了"
assert ghost_new2, "🔴 ASSERT8 失败:新 groupId 上没有 2.x 区间,方向二的幽灵不存在了"
print("   → advisory 里 %s 挂着 %d 条 3.x 区间、%s 挂着 %d 条 2.x 区间,两边在 Central 上都不存在 ✅"
      % (OLD_G, len(ghost_old3), NEW_G, len(ghost_new2)))


# ─────────── ASSERT9 ⭐ 核心主张:照单条 advisory 升级不够,必须求交集 ───────────
#
# 各维护分支的正确答案 = 该分支上所有 fixed 的**最大值**。
# 与 advisory 里出现频次最高的那个版本一比,差出来的就是「照单升级会漏的那几条」。
def _vkey(v):
    """版本排序键。预发布(rc/alpha/beta)排在同号正式版之前。"""
    m = re.match(r"^(\d+(?:\.\d+)*)(?:[.\-]?(alpha|beta|rc|m)[.\-]?(\d*))?$", v or "", re.I)
    if not m:
        return (0,), 0, 0
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums = nums + (0,) * (4 - len(nums))
    rank = {"alpha": 1, "beta": 2, "m": 1, "rc": 3}.get((m.group(2) or "").lower(), 9)
    return nums, rank, int(m.group(3) or 0)


targets = {}
for r in rows:
    if not r["fixed"]:
        continue
    k = (r["group"], r["branch"])
    cur = targets.get(k)
    if cur is None or _vkey(r["fixed"]) > _vkey(cur):
        targets[k] = r["fixed"]

# advisory 里出现频次最高的修复版(= 大多数人照抄的那个)
freq = {}
for r in rows:
    if r["fixed"]:
        freq[r["fixed"]] = freq.get(r["fixed"], 0) + 1
popular = max(freq, key=lambda v: freq[v])

print("\nASSERT9 逐分支求交集(advisory 里出现最多的是 %s,出现 %d 次):" % (popular, freq[popular]))
gap_total = 0
for (g, b), t in sorted(targets.items()):
    # 该分支上,升到"最常见的那个版本"仍然盖不住的条目
    short = sorted({r["ghsa"] for r in rows
                    if r["group"] == g and r["branch"] == b and r["fixed"]
                    and _vkey(r["fixed"]) > _vkey(min(
                        (x["fixed"] for x in rows if x["group"] == g and x["branch"] == b and x["fixed"]),
                        key=_vkey))})
    gap_total += len(short)
    print("   %-30s %-6s → %-8s %s" % (
        g, b, t, ("(该分支上有 %d 条要求比同分支最低修复版更高:%s)"
                  % (len(short), ",".join(short)) if short else "")))
assert gap_total >= 3, (
    "🔴 ASSERT9 失败:各分支内修复版完全一致(差 %d 条)—— "
    "「逐条求交集」就没有价值了,这一注的核心主张要重估" % gap_total)
print("   → 共 %d 条(分支×条目)要求高于同分支最低修复版:照单条 advisory 升级会漏 ✅" % gap_total)


# ─────────── ASSERT10/11 ⭐ 降噪表必须有区分度,且逐字来自官方原文 ───────────
kinds = {CONDITIONS[g][0] for g in official}
assert len(kinds) >= 6, (
    "🔴 ASSERT10 失败:只有 %d 种触发条件分类 —— 降噪没有区分度,退化成版本检测器" % len(kinds))
# 不允许出现「无条件」的分类 —— 那说明这条没法降噪,应显式承认而不是含糊
print("\nASSERT10 降噪区分度:%d 条 advisory 分成 %d 种触发条件 ✅" % (len(official), len(kinds)))

print("ASSERT11 降噪溯源:逐条核对锚点串是否逐字出现在官方描述原文里...")
for ghsa in order:
    kind, text, marks, anchors = CONDITIONS[ghsa]
    blob = (official[ghsa].get("description") or "") + " " + (official[ghsa].get("summary") or "")
    for anc in anchors:
        assert anc in blob, (
            "🔴 ASSERT11 失败:%s 的锚点串 %r 在官方描述原文里找不到 —— "
            "触发条件是我凭印象标的,不是原文说的\n     原文开头:%s"
            % (ghsa, anc, blob[:220]))
    for mk in marks:
        assert mk in MARKERS, "🔴 ASSERT11 失败:%s 用了未定义的源码标记 %r" % (ghsa, mk)
    print("   %-24s %-26s 锚点 %d 个全部命中 ✅" % (ghsa, kind, len(anchors)))


# ────────────────────────── 生成 Java ──────────────────────────
def jstr(s):
    return '"%s"' % (s or "").replace("\\", "\\\\").replace('"', '\\"')


def cvss_of(ghsa):
    """CVSS 分数。

    🔴 **必须两个源都看**:实测 CVE-2026-50193 在官方仓库端点上 cvss.score 是 null,
    而全局 advisory DB 里是 7.5 —— 只看一个源会在报告里印出一条没有分数的条目,
    读者会以为「这条不严重」。真实构件复验时抓到的。
    """
    for src in (official.get(ghsa), srcB[OLD_G].get(ghsa), srcB[NEW_G].get(ghsa)):
        score = ((src or {}).get("cvss") or {}).get("score")
        if score:
            return score
    return -1.0


def short_title(s, limit=100):
    """标题。

    🔴 advisory 的 summary 长度差三个数量级:短的 40 字,
    CVE-2026-59889 的是**一整段** 250+ 字(把机理和影响都写进标题里了)。
    原样印会把报告排版整个撑破,所以在这里截断而不是在渲染时截 ——
    截断规则应该和判定表一起被 diff 看见。
    """
    s = re.sub(r"\s+", " ", (s or "").strip())
    if len(s) <= limit:
        return s
    cut = s[:limit]
    sp = cut.rfind(" ")
    return (cut if sp < limit * 0.6 else cut[:sp]) + "…"


def first_sentence(text, limit=200):
    """描述原文的第一句实质内容。原文是 markdown,要跳过 '## Summary' 这类标题行。"""
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("```"):
            continue
        line = re.sub(r"[`*]", "", line)
        return line if len(line) <= limit else line[:limit - 1] + "…"
    return ""


# ASSERT12 ⭐ 每条都要有 CVSS 分数 —— 真实构件复验抓到的
#
# 🔴 CVE-2026-50193 在官方仓库端点上 cvss.score 是 null,在全局 advisory DB 里却是 7.5。
#    只看一个源,报告里那一行会印成「medium」后面空着,读者会读成「这条不严重」——
#    而它恰好是本批分数最高的一条。**同一个字段在两个源里给的不是同一份数据**,
#    而缺分数这件事既不报错也不显眼,是靠端到端看报告才发现的。
_no_cvss = [g for g in official if cvss_of(g) <= 0]
assert not _no_cvss, (
    "🔴 ASSERT12 失败:这些条目两个源都拿不到 CVSS 分数,报告里会印出空分数:%s" % _no_cvss)
print("\nASSERT12 CVSS:%d 条全部拿到分数(两个源取并集)✅" % len(official))

# ASSERT13 ⭐ 标题长度必须有界 —— 同样是复验时看报告才发现的
#
# 🔴 advisory 的 summary 长度差三个数量级:CVE-2026-59889 的是**一整段** 250+ 字,
#    原样印会把报告排版整个撑破。截断在这里做,是为了让规则和判定表一起被 diff 看见。
_long = [g for g in official if len(short_title(official[g].get("summary"))) > 105]
assert not _long, "🔴 ASSERT13 失败:这些标题截断后仍超长:%s" % _long
print("ASSERT13 标题:%d 条截断后均 ≤ 100 字 ✅" % len(official))


out = [
    "package dev.mikko.jacksoncheck;",
    "",
    "import java.util.ArrayList;",
    "import java.util.Collections;",
    "import java.util.List;",
    "",
    "/**",
    " * 由 tools/gen_rules.py 从两个一手源生成,请勿手工编辑。",
    " * 源 A:/repos/" + REPO + "/security-advisories(官方条目全集 + 描述原文)",
    " * 源 B:/advisories?ecosystem=maven&affects=&lt;坐标&gt;(Dependabot 实际用的坐标索引)",
    " *",
    " * <p>粒度是 <b>advisory × groupId × 版本区间</b>:Jackson 3 换了 groupId,",
    " * 同一条 advisory 在两个坐标、多条维护分支上的受影响区间和修复版都不同。",
    " */",
    "public final class CveTable {",
    "    private CveTable() {}",
    "",
    "    public static final String GENERATED_FROM = "
    "\"github.com/" + REPO + " security advisories + GitHub Advisory API\";",
    "",
    "    /** Jackson 2.x 的坐标。 */",
    "    public static final String GROUP_2X = " + jstr(OLD_G) + ";",
    "    /** Jackson 3.x 的坐标 —— 换了 groupId,这是本工具必须覆盖两套坐标的原因。 */",
    "    public static final String GROUP_3X = " + jstr(NEW_G) + ";",
    "    public static final String ARTIFACT = " + jstr(ART) + ";",
    "",
    "    /** 官方发布的本批条目总数(用于报告里说明覆盖范围)。 */",
    "    public static final int OFFICIAL_TOTAL = %d;" % len(official),
    "",
    "    /**",
    "     * 官方发布了、但按两个坐标都查不到的条目数 —— 即进不了 Dependabot 告警的数量。",
    "     *",
    "     * <p>🔴 本注实测为 0。这是<b>查了两个源之后</b>的结论,不是只查一个源的默认值;",
    "     * 第 8 注(shiro)用同样的方法比出来是 5 条。gen_rules.py 的 ASSERT2 每次重跑都会重新核实。",
    "     */",
    "    public static final int DEPENDABOT_BLIND = %d;" % len(blind),
    "",
    "    private static final List<Cve> ALL = new ArrayList<>();",
    "",
    "    static {",
]
for r in rows:
    ghsa = r["ghsa"]
    a = official[ghsa]
    kind, cond_text, marks, _anchors = CONDITIONS[ghsa]
    out.append("        add(%s, %s, %s, %s, %.1f, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"
               % (
                   jstr(ghsa), jstr(a.get("cve_id") or ""), jstr(r["group"]),
                   jstr(a.get("severity") or "unknown"),
                   cvss_of(ghsa),
                   jstr(r["branch"]),
                   jstr(r["low"]), "true" if r["low_incl"] else "false",
                   jstr(r["high"]), "true" if r["high_incl"] else "false",
                   jstr(r["fixed"]), "true" if r.get("fixed_ok") else "false",
                   jstr(kind), jstr(cond_text), jstr(",".join(marks)),
                   jstr(short_title(a.get("summary"))),
                   jstr(first_sentence(a.get("description")))))
out += [
    "    }",
    "",
    "    private static void add(String ghsaId, String cveId, String groupId, String severity,",
    "                            double cvss, String branch,",
    "                            String low, boolean lowIncl, String high, boolean highIncl,",
    "                            String fixedIn, boolean fixedAvailable,",
    "                            String condKind, String condText, String markers,",
    "                            String title, String desc) {",
    "        ALL.add(new Cve(ghsaId, cveId, groupId, severity, cvss, branch,",
    "                        low, lowIncl, high, highIncl, fixedIn, fixedAvailable,",
    "                        condKind, condText,",
    "                        markers.isEmpty() ? List.of() : List.of(markers.split(\",\")),",
    "                        title, desc));",
    "    }",
    "",
    "    public static List<Cve> all() { return Collections.unmodifiableList(ALL); }",
    "}",
]
os.makedirs(PKG, exist_ok=True)
with open(os.path.join(PKG, "CveTable.java"), "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")

# ── Triggers.java:源码标记表,同样生成,别在 Java 里手抄一份 ──
tg = [
    "package dev.mikko.jacksoncheck;",
    "",
    "import java.util.LinkedHashMap;",
    "import java.util.Map;",
    "import java.util.regex.Pattern;",
    "",
    "/**",
    " * 源码触发条件标记表,由 tools/gen_rules.py 生成,请勿手工编辑。",
    " *",
    " * <p>🔴 <b>只做文本匹配,不做 AST</b> —— 这是有意的设计取舍:",
    " * 关键路径必须能被人读懂并自己核对,一个看不懂的 AST 判定出错时没人能发现。",
    " * 代价是<b>匹配不到 ≠ 安全</b>(传递依赖里的库也可能用这些注解,而我们扫不到它的源码),",
    " * 报告里必须原样说出这一点。",
    " */",
    "public final class Triggers {",
    "    private Triggers() {}",
    "",
    "    /** 判断「这份源码到底用没用 jackson」的上锚。 */",
    "    public static final String ANCHOR = " + jstr(ANCHOR_MARKER) + ";",
    "",
    "    private static final Map<String, Pattern> PATTERNS = new LinkedHashMap<>();",
    "    private static final Map<String, String> LABELS = new LinkedHashMap<>();",
    "",
    "    static {",
]
for name, (rx, label) in MARKERS.items():
    tg.append("        put(%s, %s, %s);" % (jstr(name), jstr(rx), jstr(label)))
tg += [
    "    }",
    "",
    "    private static void put(String name, String regex, String label) {",
    "        PATTERNS.put(name, Pattern.compile(regex));",
    "        LABELS.put(name, label);",
    "    }",
    "",
    "    public static Map<String, Pattern> patterns() { return PATTERNS; }",
    "",
    "    public static String label(String marker) { return LABELS.getOrDefault(marker, marker); }",
    "}",
]
with open(os.path.join(PKG, "Triggers.java"), "w", encoding="utf-8") as f:
    f.write("\n".join(tg) + "\n")

print("\n✅ 已生成 CveTable.java + Triggers.java")
print("   官方 %d 条 advisory → 展开成 %d 条「advisory × 坐标 × 区间」规则" % (len(official), len(rows)))
print("   Dependabot 盲区:%d 条(两个源比对得出)" % len(blind))
print("   各分支交集目标版本:")
for (g, b), t in sorted(targets.items()):
    print("     %-30s %-6s → %s%s" % (g, b, t, "" if _probe.get((g, t), True) else "  🔴Central 上拿不到"))

json.dump({"rows": rows, "official": {k: {"cve": v.get("cve_id"), "sev": v.get("severity"),
                                          "summary": v.get("summary")} for k, v in official.items()},
           "targets": {"%s|%s" % k: v for k, v in targets.items()},
           "ghosts": ["%s|%s" % k for k in ghosts], "blind": blind},
          open(os.path.join(HERE, "rules_dump.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
