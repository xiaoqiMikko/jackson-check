package dev.mikko.jacksoncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * v0.4.0(2026-10-05)并入的 4 条:databind 的 91776 / 91777(09-30)、core 的 89425 / 89407(10-01)。
 *
 * <p>🔴 <b>这一版没有新的信息差</b>:四条发布当天就进了 GitHub 全局库,Dependabot 正常告警。
 * 并入它们只为一件事 —— v0.3.0 印出来的「一次修完」版本(2.18.10 / 2.21.6 / 3.1.6)
 * 从 09-30 起是<b>错的</b>,而工具不会因此报任何错,它只是继续安静地给出一个不够的答案。
 */
class V040Test {

    private static final String C2 = CveTable.GROUP_2X;
    private static final String C3 = CveTable.GROUP_3X;
    private static final String CORE = CveTable.ARTIFACT_CORE;
    private static final String DB = CveTable.ARTIFACT_DATABIND;

    private static Set<String> hits(String group, String artifact, String version) {
        JacksonVersion v = JacksonVersion.parse(version);
        return CveTable.all().stream()
                .filter(c -> c.groupId().equals(group) && c.artifactId().equals(artifact))
                .filter(c -> v.inRange(c.low(), c.lowIncl(), c.high(), c.highIncl()))
                .map(Cve::displayId).collect(Collectors.toSet());
    }

    private static boolean matches(String marker, String code) {
        return Triggers.patterns().get(marker).matcher(code).find();
    }

    @Test
    @DisplayName("🔴 承重:jackson-core 2.21.6(v0.3.0 给的答案)仍中 10-01 的两条,2.21.7 才清")
    void core2216IsNoLongerEnough() {
        assertEquals(Set.of("CVE-2026-89425", "CVE-2026-89407"), hits(C2, CORE, "2.21.6"));
        // 反向:单向判据和没验证长得一模一样
        assertTrue(hits(C2, CORE, "2.21.7").isEmpty(), "2.21.7 应盖住 core 2.21 线全部条目");
    }

    @Test
    @DisplayName("🔴 两条 core 新公告在 3.2 线的修复版不同:89407 修在 3.2.2,89425 要 3.2.3")
    void core32LineFixVersionsDiffer() {
        assertEquals(Set.of("CVE-2026-89425"), hits(C3, CORE, "3.2.2"),
                "3.2.2 已修 89407,但 89425 的区间是 >= 3.2.0, <= 3.2.2");
        assertTrue(hits(C3, CORE, "3.2.3").isEmpty());
    }

    @Test
    @DisplayName("四条新公告都在 GitHub 全局库里 —— 不许写成「Dependabot 不报」")
    void newFourAreAllInGlobalDb() {
        List<Cve> four = CveTable.all().stream()
                .filter(c -> Set.of("CVE-2026-91776", "CVE-2026-91777",
                        "CVE-2026-89425", "CVE-2026-89407").contains(c.cveId()))
                .toList();
        assertEquals(4, four.stream().map(Cve::cveId).distinct().count(), "四条都得在判定表里");
        assertTrue(four.stream().allMatch(Cve::inGlobalDb));
    }

    @Test
    @DisplayName("defaultImpl 只认赋值写法;@JsonIdentityInfo 不吞并更长的标识符")
    void newMarkers() {
        assertTrue(matches("defaultImpl",
                "@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, defaultImpl = Fallback.class)"));
        assertTrue(matches("defaultImpl", "@JsonTypeInfo(use=Id.NAME,defaultImpl=Fallback.class)"));
        assertFalse(matches("defaultImpl", "// 这里没有配 defaultImpl 兜底"));
        assertFalse(matches("defaultImpl", "String myDefaultImpl = null;"));

        assertTrue(matches("@JsonIdentityInfo",
                "@JsonIdentityInfo(generator = ObjectIdGenerators.IntSequenceGenerator.class)"));
        assertFalse(matches("@JsonIdentityInfo", "@JsonIdentityInfoX"));
        assertFalse(matches("@JsonIdentityInfo", "@JsonIdentityReference(alwaysAsId = true)"));
    }

    @Test
    @DisplayName("91776 的触发条件要求 @JsonTypeInfo 与 defaultImpl 两个标记")
    void rule91776NeedsBothMarkers() {
        Cve c = CveTable.all().stream().filter(x -> "CVE-2026-91776".equals(x.cveId()))
                .findFirst().orElseThrow();
        assertEquals(DB, c.artifactId());
        assertEquals(List.of("@JsonTypeInfo", "defaultImpl"), c.markers());
    }
}
