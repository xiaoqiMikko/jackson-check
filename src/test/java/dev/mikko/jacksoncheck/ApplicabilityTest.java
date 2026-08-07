package dev.mikko.jacksoncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApplicabilityTest {

    private static List<Scanner.Artifact> art(String group, String version) {
        return List.of(new Scanner.Artifact("test.jar", group, JacksonVersion.parse(version),
                "pom.properties", false));
    }

    private static SourceScan src(Path dir, String content) throws IOException {
        Files.write(dir.resolve("X.java"), content.getBytes(StandardCharsets.UTF_8));
        SourceScan s = new SourceScan();
        s.scan(dir);
        return s;
    }

    /** 真实判定表里第一条针对 @JsonView 的规则(CVE-2026-54517)。 */
    private static Cve jsonViewRule() {
        return CveTable.all().stream()
                .filter(c -> c.condKind().equals("JSONVIEW") && c.groupId().equals(CveTable.GROUP_2X))
                .findFirst().orElseThrow();
    }

    @Test
    @DisplayName("没扫到对应坐标 → NOT_PRESENT")
    void notPresent() {
        Cve c = jsonViewRule();
        Applicability.Verdict v = Applicability.judge(c, art(CveTable.GROUP_3X, "3.1.2"), null);
        assertEquals(Applicability.Kind.NOT_PRESENT, v.kind(),
                "这条挂在 2.x 坐标上,只装了 3.x 的人不中");
    }

    @Test
    @DisplayName("版本不在区间内 → VERSION_SAFE")
    void versionSafe() {
        Cve c = jsonViewRule();
        Applicability.Verdict v = Applicability.judge(c, art(CveTable.GROUP_2X, "2.21.9"), null);
        assertEquals(Applicability.Kind.VERSION_SAFE, v.kind());
        assertFalse(v.versionHit());
    }

    @Test
    @DisplayName("版本中 + 触发条件全部找到 → HIT")
    void fullHit(@TempDir Path dir) throws IOException {
        Cve c = jsonViewRule();
        SourceScan s = src(dir, """
                public class X {
                    @JsonView(Admin.class)
                    List<String> roles;
                }
                """);
        Applicability.Verdict v = Applicability.judge(c, art(CveTable.GROUP_2X, "2.21.2"), s);
        assertEquals(Applicability.Kind.HIT, v.kind());
        assertTrue(v.triggered());
        assertTrue(v.found().contains("@JsonView"));
    }

    @Test
    @DisplayName("🔴 版本中 + 一个标记都没找到 → VERSION_HIT_NO_TRIGGER,而且绝不从报告里消失")
    void versionHitWithoutTrigger(@TempDir Path dir) throws IOException {
        Cve c = jsonViewRule();
        SourceScan s = src(dir, """
                public class X {
                    ObjectMapper m = new ObjectMapper();
                }
                """);
        Applicability.Verdict v = Applicability.judge(c, art(CveTable.GROUP_2X, "2.21.2"), s);
        assertEquals(Applicability.Kind.VERSION_HIT_NO_TRIGGER, v.kind());
        assertTrue(v.versionHit(), "🔴 版本仍然是中的 —— 降噪只降级不排除");
        assertFalse(v.triggered());
        assertTrue(v.reason().contains("不等于安全"), "措辞必须挡住「扫过就没事」的误读");
    }

    @Test
    @DisplayName("部分标记命中 → HIT_PARTIAL(要人看一眼)")
    void partialHit(@TempDir Path dir) throws IOException {
        // CVE-2026-54518 / 59889 要求 @JsonView 和 @JsonUnwrapped 同时存在
        Cve c = CveTable.all().stream()
                .filter(x -> x.condKind().equals("JSONVIEW_UNWRAPPED")
                        && x.groupId().equals(CveTable.GROUP_2X))
                .findFirst().orElseThrow();
        SourceScan s = src(dir, "public class X { @JsonView(A.class) String s; }\n");
        Applicability.Verdict v = Applicability.judge(c, art(CveTable.GROUP_2X, "2.21.2"), s);
        assertEquals(Applicability.Kind.HIT_PARTIAL, v.kind());
        assertTrue(v.found().contains("@JsonView"));
        assertTrue(v.missing().contains("@JsonUnwrapped"));
    }

    @Test
    @DisplayName("🔴 没扫源码 ≠ 部分成立 —— 必须是独立的一档")
    void noSourceScanIsItsOwnKind() {
        // 由来(真实构件复验抓到):扫一个 fat jar(里面没有 .java)时,
        // 原本会把命中的条目全印成「触发条件部分成立」—— 那句话是假的,
        // 我们根本没看过任何源码。「没做判断」和「判断结果是一半」长得像,含义完全不同。
        Cve c = jsonViewRule();
        Applicability.Verdict v = Applicability.judge(c, art(CveTable.GROUP_2X, "2.21.2"), null);
        assertEquals(Applicability.Kind.NO_SOURCE_SCAN, v.kind());
        assertTrue(v.versionHit(), "版本仍然是中的,不能消失");
        assertFalse(v.triggered(), "没有依据说它触发了");
        assertTrue(v.reason().contains("没做"));
    }

    @Test
    @DisplayName("🔴 同时装两个 groupId 时,同一条在两个坐标上都中,一条都不能丢")
    void bothGroupIdsHitSameAdvisory(@TempDir Path dir) throws IOException {
        // 由来(真实构件复验抓到):升级中途 classpath 上同时有 2.x 和 3.x 的 jackson,
        // CVE-2026-54515 在 2.21.2 和 3.1.2 上都中。按「条目」归并只会留下一条,
        // 用户看到的版本号是另一个坐标的 —— 那是安静地丢掉一半信息。
        List<Scanner.Artifact> both = List.of(
                new Scanner.Artifact("v2.jar", CveTable.GROUP_2X,
                        JacksonVersion.parse("2.21.2"), "pom.properties", false),
                new Scanner.Artifact("v3.jar", CveTable.GROUP_3X,
                        JacksonVersion.parse("3.1.2"), "pom.properties", false));
        List<Cve> hits = CveTable.all().stream()
                .filter(c -> c.ghsaId().equals("GHSA-5jmj-h7xm-6q6v"))   // CVE-2026-54515
                .filter(c -> Applicability.judge(c, both, null).versionHit())
                .toList();
        long groups = hits.stream().map(Cve::groupId).distinct().count();
        assertEquals(2, groups, "这一条在两个坐标上都该中,报告的归并键必须含 groupId");
    }

    @Test
    @DisplayName("🔴 同一坐标有多个版本时,任一命中即命中")
    void anyVersionHits(@TempDir Path dir) throws IOException {
        Cve c = jsonViewRule();
        List<Scanner.Artifact> two = List.of(
                new Scanner.Artifact("new.jar", CveTable.GROUP_2X,
                        JacksonVersion.parse("2.21.9"), "pom.properties", false),
                new Scanner.Artifact("old.jar", CveTable.GROUP_2X,
                        JacksonVersion.parse("2.21.2"), "pom.properties", false));
        SourceScan s = src(dir, "public class X { @JsonView(A.class) List<String> r; }\n");
        Applicability.Verdict v = Applicability.judge(c, two, s);
        assertEquals(Applicability.Kind.HIT, v.kind(),
                "老 WAR 里塞着两代 jar,挑新的那份判会漏掉老的那份");
        assertEquals("2.21.2", v.version().toString());
    }

    @Test
    @DisplayName("降噪确实降下来了:同一个版本,有无 @JsonView 的结果条数不同")
    void denoiseActuallyReducesCount(@TempDir Path dir) throws IOException {
        SourceScan bare = src(dir, "public class X { ObjectMapper m = new ObjectMapper(); }\n");
        Path dir2 = Files.createTempDirectory("rich");
        SourceScan rich = src(dir2, """
                public class X {
                    ObjectMapper m = new ObjectMapper();
                    @JsonView(Admin.class) @JsonUnwrapped Address a;
                    @JsonTypeInfo(use = Id.CLASS) Object o;
                    PolymorphicTypeValidator ptv;
                }
                """);
        long bareHits = CveTable.all().stream()
                .filter(c -> Applicability.judge(c, art(CveTable.GROUP_2X, "2.21.2"), bare).triggered())
                .map(Cve::ghsaId).distinct().count();
        long richHits = CveTable.all().stream()
                .filter(c -> Applicability.judge(c, art(CveTable.GROUP_2X, "2.21.2"), rich).triggered())
                .map(Cve::ghsaId).distinct().count();
        assertTrue(richHits > bareHits,
                "用了这些特性的代码该中更多条(" + richHits + " vs " + bareHits + ")");
        long versionHits = CveTable.all().stream()
                .filter(c -> Applicability.judge(c, art(CveTable.GROUP_2X, "2.21.2"), bare).versionHit())
                .map(Cve::ghsaId).distinct().count();
        assertTrue(versionHits > richHits,
                "🔥 降噪的价值就在这个差:Dependabot 报 " + versionHits + " 条,真中 " + richHits + " 条");
    }
}
