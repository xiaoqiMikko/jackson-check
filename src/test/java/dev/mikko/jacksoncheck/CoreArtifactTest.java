package dev.mikko.jacksoncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * v0.3.0 的核心能力:<b>jackson-core 是另一个独立发版的坐标</b>。
 *
 * <p>🔴 <b>这一整个测试类存在的理由</b>:v0.2.x 的判定表整张只有 {@code jackson-databind}
 * 一个 artifactId,于是 {@code CVE-2026-68498}(high 7.5,2026-09-12)一条都扫不出来 ——
 * <b>而工具不会因此报任何错,它只是安静地什么都不说。</b>
 * 「没扫到」和「你很安全」在报告里长得一模一样,这类静默失败是本项目最贵的一类。
 */
class CoreArtifactTest {

    private static final String C2 = CveTable.GROUP_2X;
    private static final String C3 = CveTable.GROUP_3X;
    private static final String CORE = CveTable.ARTIFACT_CORE;
    private static final String DB = CveTable.ARTIFACT_DATABIND;

    private static Scanner.Artifact art(String group, String artifact, String version) {
        return new Scanner.Artifact(artifact + ".jar", group, artifact,
                JacksonVersion.parse(version), "pom.properties", false);
    }

    /** 真实判定表里 CVE-2026-68498 在 2.x 坐标上的那几条规则。 */
    private static List<Cve> rule68498() {
        List<Cve> rs = CveTable.all().stream()
                .filter(c -> "CVE-2026-68498".equals(c.cveId()))
                .toList();
        assertFalse(rs.isEmpty(), "判定表里必须有 CVE-2026-68498 —— 没有就是 v0.3.0 白做了");
        return rs;
    }

    @Test
    @DisplayName("🔴 承重:只装 jackson-databind 的人,core 的规则判 NOT_PRESENT —— 不能冒充成安全")
    void databindOnlyDoesNotCoverCore() {
        Cve c = rule68498().stream()
                .filter(x -> x.groupId().equals(C2) && "2.21.6".equals(x.fixedIn()))
                .findFirst().orElseThrow();
        assertEquals(CORE, c.artifactId(), "68498 挂在 jackson-core 上");

        // 只扫到 databind,而且是已经升过的 2.21.6 —— 照 v0.2.x 的逻辑会看起来「全清」
        Applicability.Verdict v = Applicability.judge(c, List.of(art(C2, DB, "2.21.6")), null);
        assertEquals(Applicability.Kind.NOT_PRESENT, v.kind(),
                "databind 升到 2.21.6 不代表 core 也升了 —— 必须报「未扫到这个坐标」而不是安全");
        assertTrue(v.reason().contains(CORE), "理由里要点名缺的是哪个坐标:" + v.reason());
    }

    @Test
    @DisplayName("🔴 承重:jackson-core 2.21.5 命中 68498,答案是 2.21.6")
    void core2215IsHit() {
        Cve c = rule68498().stream()
                .filter(x -> x.groupId().equals(C2) && "2.21.6".equals(x.fixedIn()))
                .findFirst().orElseThrow();
        Applicability.Verdict v = Applicability.judge(c, List.of(art(C2, CORE, "2.21.5")), null);
        assertTrue(v.versionHit(), "2.21.5 落在 >= 2.19.0, <= 2.21.5 里");

        // 反向:升到 2.21.6 就不中了(单向判据和没验证长得一模一样)
        Applicability.Verdict safe = Applicability.judge(c, List.of(art(C2, CORE, "2.21.6")), null);
        assertEquals(Applicability.Kind.VERSION_SAFE, safe.kind(), "2.21.6 已修");
    }

    @Test
    @DisplayName("🔴 承重:databind 和 core 都装了老版本 → 必须给出**两个**升级目标,不许合成一个")
    void twoCoordinatesTwoPlans() {
        List<Scanner.Artifact> scanned = List.of(art(C2, DB, "2.21.2"), art(C2, CORE, "2.21.2"));
        JacksonVersion v = JacksonVersion.parse("2.21.2");
        List<Cve> hits = CveTable.all().stream()
                .filter(c -> c.groupId().equals(C2))
                .filter(c -> v.inRange(c.low(), c.lowIncl(), c.high(), c.highIncl()))
                .toList();

        List<Remediation.Plan> plans = Remediation.plan(hits, scanned);
        List<String> coords = plans.stream().map(Remediation.Plan::coord).sorted().toList();
        assertEquals(List.of(C2 + ":" + CORE, C2 + ":" + DB), coords,
                "两个坐标各给一个目标 —— 混成一组求交集会得出一个对谁都不对的版本号");
    }

    @Test
    @DisplayName("🔴 core 侧的全局库盲区正好 1 条 —— 其余 6 条 Dependabot 正常报,不许说过头")
    void onlyOneCoreBlindSpot() {
        long blind = CveTable.all().stream()
                .filter(c -> c.artifactId().equals(CORE))
                .filter(c -> !c.inGlobalDb())
                .map(Cve::ghsaId).distinct().count();
        assertEquals(1, blind,
                "只有 CVE-2026-68498 查不到;写「Dependabot 对 jackson-core 全瞎」会被一查就抓");
    }

    @Test
    @DisplayName("两个 groupId 上都要有 core 规则 —— 3.x 换了坐标,只覆盖 2.x 等于对 Jackson 3 用户无效")
    void coreCoversBothGroups() {
        for (String g : new String[]{C2, C3}) {
            long n = CveTable.all().stream()
                    .filter(c -> c.artifactId().equals(CORE) && c.groupId().equals(g)).count();
            assertTrue(n > 0, "缺 " + g + ":" + CORE + " 的规则");
        }
    }
}
