package dev.mikko.jacksoncheck;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 命令行入口。
 *
 * <p>用法:{@code java -jar jackson-check.jar <路径...> [选项]}
 *
 * <p>路径可以是 jar / war / 目录。目录会**同时**找构建产物和 {@code .java} 源码 ——
 * 前者定版本,后者定触发条件,两个都有才答得出「11 条里你真中几条」。
 */
public final class Main {

    private static final String VERSION = "0.1.0";

    /** 退出码:0 = 没有版本命中;2 = 版本命中但源码里没找到触发条件;3 = 触发条件也成立。 */
    private static final int EXIT_CLEAN = 0;
    private static final int EXIT_VERSION_ONLY = 2;
    private static final int EXIT_TRIGGERED = 3;

    public static void main(String[] args) throws IOException {
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);

        List<Path> targets = new ArrayList<>();
        List<Path> srcDirs = new ArrayList<>();
        boolean scanSrc = true;
        boolean showAll = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-h", "--help" -> {
                    usage(out);
                    return;
                }
                case "-v", "--version" -> {
                    out.println("jackson-check " + VERSION);
                    return;
                }
                case "--no-src" -> scanSrc = false;
                case "--all" -> showAll = true;
                case "--src" -> {
                    if (++i >= args.length) {
                        out.println("🔴 --src 后面要跟一个路径");
                        System.exit(1);
                    }
                    srcDirs.add(Paths.get(args[i]));
                }
                default -> {
                    if (args[i].startsWith("-")) {
                        out.println("🔴 未知选项:" + args[i]);
                        usage(out);
                        System.exit(1);
                    }
                    targets.add(Paths.get(args[i]));
                }
            }
        }
        if (targets.isEmpty() && srcDirs.isEmpty()) {
            usage(out);
            System.exit(1);
        }

        Scanner scanner = new Scanner();
        for (Path t : targets) {
            scanner.scan(t);
        }

        SourceScan src = null;
        if (scanSrc) {
            src = new SourceScan();
            for (Path t : srcDirs) {
                src.scan(t);
            }
            for (Path t : targets) {
                if (Files.isDirectory(t)) {
                    src.scan(t);
                }
            }
            if (src.filesScanned() == 0 && srcDirs.isEmpty()) {
                // 没扫到任何 .java —— 降噪这一步做不了,必须说清楚而不是默默按「没触发条件」处理
                src = null;
            }
        }

        report(out, scanner, src, showAll);

        int code = EXIT_CLEAN;
        for (Cve c : CveTable.all()) {
            Applicability.Verdict v = Applicability.judge(c, scanner.artifacts(), src);
            if (v.triggered()) {
                code = EXIT_TRIGGERED;
                break;
            }
            if (v.versionHit()) {
                code = EXIT_VERSION_ONLY;
            }
        }
        System.exit(code);
    }

    private static void usage(PrintStream out) {
        out.println("""
                jackson-check %s —— jackson-databind 2026 年 %d 条安全公告自查

                用法:java -jar jackson-check.jar <路径...> [选项]

                  <路径>        jar / war / 目录。目录会同时找构建产物(定版本)和 .java 源码(定触发条件)
                  --src <路径>  额外指定源码目录
                  --no-src      不扫源码(只按版本判,等同于 Dependabot 的粒度)
                  --all         把未命中的条目也列出来
                  -v, --version 版本号
                  -h, --help    本帮助

                退出码:0 = 版本没中;2 = 版本中但源码里没找到触发条件;3 = 触发条件也成立

                例:
                  java -jar jackson-check.jar ./target ./src
                  java -jar jackson-check.jar app.war
                  java -jar jackson-check.jar ~/.m2/repository --no-src
                """.formatted(VERSION, CveTable.OFFICIAL_TOTAL));
    }

    private static void report(PrintStream out, Scanner scanner, SourceScan src, boolean showAll) {
        List<Scanner.Artifact> arts = scanner.artifacts();

        out.println("=".repeat(78));
        out.println("jackson-check " + VERSION + " —— jackson-databind "
                + CveTable.OFFICIAL_TOTAL + " 条 2026 年安全公告自查");
        out.println("判定表来源:" + CveTable.GENERATED_FROM);
        out.println("=".repeat(78));

        // ── 一、扫到了什么 ──
        out.println();
        out.println("【一】扫到的 jackson-databind");
        if (arts.isEmpty()) {
            out.println("  未扫到任何 jackson-databind 构件。");
            out.println("  ⚠️ 这可能是因为你传的路径里没有构建产物 —— 先跑一次构建,再扫 target/ 或 jar 本身。");
        } else {
            for (Scanner.Artifact a : arts) {
                out.printf("  %-30s %-12s  (版本来源:%s%s)%n", a.groupId(), a.version(),
                        a.source(), a.guessedGroup() ? ",groupId 按大版本推断" : "");
                out.println("      " + a.path());
            }
            Set<String> groups = new LinkedHashSet<>();
            arts.forEach(a -> groups.add(a.groupId()));
            if (groups.size() > 1) {
                out.println("  ⚠️ 同时扫到两个坐标的 jackson-databind。Jackson 3 换了 groupId,");
                out.println("     两份会同时出现在 classpath 上 —— 这本身通常是依赖冲突,建议先统一。");
            }
        }

        // ── 二、源码触发条件 ──
        out.println();
        out.println("【二】源码里的触发条件");
        if (src == null) {
            out.println("  本次未扫描源码(没传源码目录或用了 --no-src)。");
            out.println("  🔴 没有这一步就没有降噪 —— 下面会把版本命中的条目全部列出,粒度等同 Dependabot。");
        } else {
            out.printf("  扫了 %d 个 .java 文件%n", src.filesScanned());
            if (!src.usesJackson()) {
                out.println("  ⚠️ 源码里没有出现 " + Triggers.ANCHOR + " —— 这份源码可能根本没直接用 jackson,");
                out.println("     那么下面的「未找到触发条件」说明不了什么(用 jackson 的是你依赖的库)。");
            }
            List<String> shown = new ArrayList<>();
            for (Map.Entry<String, Integer> e : src.counts().entrySet()) {
                if (e.getKey().equals(Triggers.ANCHOR)) {
                    continue;
                }
                shown.add(String.format("  %-36s %d 处", Triggers.label(e.getKey()), e.getValue()));
            }
            if (shown.isEmpty()) {
                out.println("  没找到任何触发条件标记。");
            } else {
                shown.forEach(out::println);
                out.println("  证据(每类最多 5 条):");
                src.hits().forEach((k, v) -> {
                    if (!k.equals(Triggers.ANCHOR)) {
                        // 标上是哪个标记的证据 —— 同一行可能同时命中多个标记
                        // (@JsonTypeInfo 那行也含 EXTERNAL_PROPERTY),不标就看不出来是两类
                        v.forEach(ev -> out.printf("    [%s] %s%n", k, ev));
                    }
                });
            }
        }

        // ── 三、逐条判定 ──
        // 🔴 归并粒度是「条目 × 坐标」而不是「条目」。
        //    真实构件复验时抓到:同时装了两个 groupId 的 jackson(升级中途很常见)时,
        //    CVE-2026-54515 在 2.21.2 和 3.1.2 上**都中**,按条目归并只会留下其中一条,
        //    用户看到的版本号是另一个坐标的 —— 那是安静地丢掉了一半信息。
        Map<String, Applicability.Verdict> best = new LinkedHashMap<>();
        Map<String, Cve> repr = new LinkedHashMap<>();
        List<Cve> versionHitRules = new ArrayList<>();
        for (Cve c : CveTable.all()) {
            Applicability.Verdict v = Applicability.judge(c, arts, src);
            if (v.versionHit()) {
                versionHitRules.add(c);
            }
            String key = c.ghsaId() + "|" + c.groupId();
            Applicability.Verdict cur = best.get(key);
            if (cur == null || rank(v.kind()) > rank(cur.kind())) {
                best.put(key, v);
                repr.put(key, c);
            }
        }
        // 但**计数**要按条目去重 —— 「你中了几条」问的是漏洞数,不是规则数。
        Set<String> triggeredIds = new LinkedHashSet<>();
        Set<String> versionHitIds = new LinkedHashSet<>();
        best.forEach((k, v) -> {
            String id = repr.get(k).ghsaId();
            if (v.triggered()) {
                triggeredIds.add(id);
            }
            if (v.versionHit()) {
                versionHitIds.add(id);
            }
        });
        long triggered = triggeredIds.size();
        long versionHit = versionHitIds.size();

        out.println();
        out.println("【三】判定结果");
        out.println("  " + "-".repeat(74));
        out.printf("  Dependabot 会报给你:%d 条(装了受影响版本就报)%n", versionHit);
        if (src != null) {
            out.printf("  源码里触发条件成立的:%d 条  ← 这才是你真正要先处理的%n", triggered);
        }
        out.println("  " + "-".repeat(74));

        for (Applicability.Kind k : new Applicability.Kind[]{
                Applicability.Kind.HIT, Applicability.Kind.HIT_PARTIAL,
                Applicability.Kind.NO_SOURCE_SCAN,
                Applicability.Kind.VERSION_HIT_NO_TRIGGER,
                Applicability.Kind.VERSION_SAFE, Applicability.Kind.NOT_PRESENT}) {
            List<String> ids = best.entrySet().stream()
                    .filter(e -> e.getValue().kind() == k).map(Map.Entry::getKey).toList();
            if (ids.isEmpty()) {
                continue;
            }
            boolean detail = k != Applicability.Kind.VERSION_SAFE
                    && k != Applicability.Kind.NOT_PRESENT || showAll;
            out.println();
            out.println("  " + kindLabel(k) + "(" + ids.size() + " 条)");
            for (String id : ids) {
                Cve c = repr.get(id);
                Applicability.Verdict v = best.get(id);
                out.printf("    %-22s %-8s %s%n", c.displayId(),
                        c.severity() + (c.cvss() > 0 ? " " + c.cvss() : ""), c.title());
                if (!detail) {
                    continue;
                }
                out.println("        坐标   " + c.groupId() + " · 你的版本 " + v.version()
                        + " · 受影响 " + c.rangeText());
                out.println("        条件   " + c.condText());
                if (!v.found().isEmpty()) {
                    out.println("        命中   " + String.join("、", v.found()));
                }
                if (!v.missing().isEmpty()) {
                    out.println("        未找到 " + String.join("、", v.missing()));
                }
                if (!v.reason().isEmpty()) {
                    out.println("        说明   " + v.reason());
                }
                if (c.cveId().isEmpty()) {
                    out.println("        ⚠️ 这条**没有 CVE 号**,按 CVE 编号搜是搜不到的:"
                            + "https://github.com/advisories/" + c.ghsaId());
                }
            }
        }

        // ── 四、升级建议(逐条求交集)──
        out.println();
        out.println("【四】该升到哪个版本(逐条求交集,不是照抄某一条 advisory)");
        List<Remediation.Plan> plans = Remediation.plan(versionHitRules, arts);
        if (plans.isEmpty()) {
            out.println("  没有需要升级的坐标。");
        } else {
            for (Remediation.Plan p : plans) {
                out.printf("  %s%n", p.groupId());
                out.printf("      现在 %s  →  升到 %s%s%n",
                        p.current() == null ? "(未知)" : p.current(), p.target(),
                        p.available() ? "" : "  🔴 这个版本在 Maven Central 上拿不到");
                out.println("      盖住 " + p.covers().size() + " 条;把目标顶到这么高的是 " + p.drivenBy());
                if (p.crossBranch()) {
                    out.println("      ⚠️ 跨维护分支升级(" + p.current().branch() + " → "
                            + JacksonVersion.parse(p.target()).branch() + "),改动比补丁版大,先跑回归");
                }
                if (!p.available()) {
                    out.println("      🔴 advisory 把这个修复版挂在了错的坐标上 —— "
                            + "Central 上 " + p.groupId() + " 根本没有发布过这条大版本线,详见【五】");
                }
            }
            List<Cve> beyond = Remediation.beyondLowestFix(versionHitRules);
            if (!beyond.isEmpty()) {
                Set<String> ids = new LinkedHashSet<>();
                beyond.forEach(c -> ids.add(c.displayId()));
                out.println();
                out.println("  🔥 注意:如果你照着 advisory 里出现最多的那个修复版升,以下 "
                        + ids.size() + " 条仍然中:");
                out.println("     " + String.join("、", ids));
                out.println("     这就是为什么要逐条求交集 —— 单看任何一条 advisory 都得不出上面那个目标版本。");
            }
        }

        // ── 五、两个 groupId 与幽灵坐标 ──
        long ghost = CveTable.all().stream().filter(c -> !c.fixedIn().isEmpty() && !c.fixedAvailable()).count();
        out.println();
        out.println("【五】关于两个 groupId");
        out.println("  Jackson 3 换了坐标:" + CveTable.GROUP_2X + "(2.x)→ " + CveTable.GROUP_3X + "(3.x),");
        out.println("  artifactId 和 jar 文件名完全一样,只有 META-INF 里分得清 —— 本工具按坐标判,不按文件名。");
        if (ghost > 0) {
            out.println("  🔴 advisory 在这两个坐标之间贴串了版本区间:共 " + ghost
                    + " 条规则的修复版在对应坐标下是 HTTP 404。");
            out.println("     照抄 advisory 的工具会让你去装一个不存在的东西。本工具已逐个实测并标注。");
        }

        // ── 六、边界(不许暗示「扫过就没事」)──
        out.println();
        out.println("【六】🔴 这个报告不能证明什么");
        out.println("  两个方向都要说清楚 —— 只说一边就是在误导。");
        out.println();
        out.println("  ① 「未找到触发条件」**不等于安全**,至少三种情况会让它变成假的安心:");
        out.println("     1. 你依赖的第三方库在**它自己的代码**里用了这些注解 —— 我们扫不到它的源码;");
        out.println("     2. 注解可能通过 mixin(ObjectMapper.addMixIn)等运行时方式加上,源码里没有那个词;");
        out.println("     3. 你可能压根没把源码目录传进来。");
        out.println();
        out.println("  ② 「触发条件全部成立」**也不等于确认中招**:");
        out.println("     标记是按**整个代码库**聚合的,不是按同一个类或同一个字段。");
        out.println("     比如某条要求 @JsonView 和 @JsonUnwrapped 标在**同一个属性**上,");
        out.println("     而我们只能看到这两个词都在你的代码里出现过 —— 这只够用来**排优先级**。");
        out.println();
        out.println("  本工具只做**文本匹配,不做 AST 解析** —— 这是为了让关键路径能被人读懂并自己核对。");
        out.println("  版本判定(第一步)是硬的;触发条件判定(第二步)只用来排序,不用来免除风险。");
        out.println();
        out.println("  Dependabot 盲区:本批 " + CveTable.OFFICIAL_TOTAL + " 条里有 "
                + CveTable.DEPENDABOT_BLIND + " 条按坐标查不到。");
        out.println("  → " + (CveTable.DEPENDABOT_BLIND == 0
                ? "也就是说这一批 Dependabot 的**版本告警是准的**,本工具的价值在降噪和求交集,不在补漏。"
                : "这些条目进不了 Dependabot 告警,只能靠本工具发现。"));

        List<String> warns = new ArrayList<>(scanner.warnings());
        if (src != null) {
            warns.addAll(src.warnings());
        }
        if (!warns.isEmpty()) {
            out.println();
            out.println("【七】扫描过程中的告警(" + warns.size() + " 条)");
            warns.forEach(w -> out.println("  ⚠️ " + w));
        }
        out.println();
    }

    private static int rank(Applicability.Kind k) {
        return switch (k) {
            case HIT -> 6;
            case HIT_PARTIAL -> 5;
            case NO_SOURCE_SCAN -> 4;
            case VERSION_HIT_NO_TRIGGER -> 3;
            case VERSION_SAFE -> 2;
            case NOT_PRESENT -> 1;
        };
    }

    private static String kindLabel(Applicability.Kind k) {
        return switch (k) {
            case HIT -> "🔴 版本中 + 触发条件全部成立";
            case HIT_PARTIAL -> "🟠 版本中 + 触发条件部分成立";
            case NO_SOURCE_SCAN -> "🟠 版本中(本次没扫源码,降噪没做 —— 粒度等同 Dependabot)";
            case VERSION_HIT_NO_TRIGGER -> "🟡 版本中,但源码里没找到触发条件(≠ 安全,见【六】)";
            case VERSION_SAFE -> "🟢 版本不在受影响区间内";
            case NOT_PRESENT -> "⚪ 没扫到这条针对的坐标";
        };
    }

    private Main() {
    }
}
