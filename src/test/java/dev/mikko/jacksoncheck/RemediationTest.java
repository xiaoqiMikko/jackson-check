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
 * 求交集是本工具最硬的一块 —— 它给出的那个版本号,是「照单条 advisory 升级」得不到的。
 * 这里用**真实判定表**测,不用捏造数据:捏出来的表测的是我自己的想象。
 */
class RemediationTest {

    /** 拿真实判定表里对某个版本命中的规则。 */
    private static List<Cve> hitsFor(String group, String version) {
        JacksonVersion v = JacksonVersion.parse(version);
        return CveTable.all().stream()
                .filter(c -> c.groupId().equals(group))
                .filter(c -> v.inRange(c.low(), c.lowIncl(), c.high(), c.highIncl()))
                .toList();
    }

    private static List<Scanner.Artifact> art(String group, String version) {
        return List.of(new Scanner.Artifact("test.jar", group, JacksonVersion.parse(version),
                "pom.properties", false));
    }

    @Test
    @DisplayName("🔥 2.21.2 的答案是 2.21.5,不是 advisory 里反复出现的 2.21.4")
    void jackson221TargetIsNot2214() {
        List<Cve> hits = hitsFor(CveTable.GROUP_2X, "2.21.2");
        assertFalse(hits.isEmpty(), "2.21.2 应该中不少条");
        List<Remediation.Plan> plans = Remediation.plan(hits, art(CveTable.GROUP_2X, "2.21.2"));
        assertEquals(1, plans.size(), "2.x 只该给一个升级目标");
        assertEquals("2.21.5", plans.get(0).target(),
                "8 条 advisory 都写 2.21.4,但 CVE-2026-54515 / 59889 / GHSA-mhm7 要 2.21.5");
        assertTrue(plans.get(0).available(), "2.21.5 在 Central 上拿得到");
    }

    @Test
    @DisplayName("🔥 2.18.5 的答案是 2.18.9,不是 2.18.8")
    void jackson218TargetIsNot2188() {
        List<Cve> hits = hitsFor(CveTable.GROUP_2X, "2.18.5");
        List<Remediation.Plan> plans = Remediation.plan(hits, art(CveTable.GROUP_2X, "2.18.5"));
        assertEquals("2.18.9", plans.get(0).target());
    }

    @Test
    @DisplayName("🔥 Jackson 3.1.2 的答案是 3.1.5,不是 3.1.4")
    void jackson31TargetIsNot314() {
        List<Cve> hits = hitsFor(CveTable.GROUP_3X, "3.1.2");
        assertFalse(hits.isEmpty());
        List<Remediation.Plan> plans = Remediation.plan(hits, art(CveTable.GROUP_3X, "3.1.2"));
        assertEquals("3.1.5", plans.get(0).target(),
                "多数条目写 3.1.4,而 CVE-2026-59889 要 3.1.5");
    }

    @Test
    @DisplayName("🔴 GHSA-mhm7(没有 CVE 号的那条)必须出现在「照单升级会漏」的名单里")
    void patchGapEntryIsInTheGapList() {
        List<Cve> hits = hitsFor(CveTable.GROUP_2X, "2.21.2");
        Set<String> beyond = Remediation.beyondLowestFix(hits).stream()
                .map(Cve::displayId).collect(Collectors.toSet());
        assertTrue(beyond.contains("GHSA-mhm7-754m-9p8w"),
                "它的 advisory 原文明写「升到 2.21.4 的人仍然中招」,必须被算进去");
        assertTrue(beyond.size() >= 2, "不止一条要求高于最低修复版");
    }

    @Test
    @DisplayName("已经升到 2.21.5 的人,2.21 线上不该再中")
    void patchedVersionIsClean() {
        List<Cve> hits = hitsFor(CveTable.GROUP_2X, "2.21.5");
        assertTrue(hits.isEmpty(), "2.21.5 应该盖住 2.21 线全部条目,实际还中:"
                + hits.stream().map(Cve::displayId).collect(Collectors.toSet()));
    }

    @Test
    @DisplayName("🔴 升到 advisory 里最常见的 2.21.4,仍然中 —— 这就是本工具的卖点")
    void popularFixIsNotEnough() {
        List<Cve> hits = hitsFor(CveTable.GROUP_2X, "2.21.4");
        assertFalse(hits.isEmpty(),
                "如果 2.21.4 就干净了,「求交集」这个卖点不成立,文案要改");
        Set<String> ids = hits.stream().map(Cve::displayId).collect(Collectors.toSet());
        assertTrue(ids.contains("GHSA-mhm7-754m-9p8w"), "补丁缺口那条必须还在");
    }

    @Test
    @DisplayName("2.x 用户不该被推去升 3.x(那是换 groupId 的破坏性升级)")
    void neverPushAcrossMajorLines() {
        List<Cve> hits = hitsFor(CveTable.GROUP_2X, "2.18.5");
        for (Remediation.Plan p : Remediation.plan(hits, art(CveTable.GROUP_2X, "2.18.5"))) {
            assertTrue(p.target().startsWith("2."), "2.x 用户的升级目标必须还在 2.x:" + p.target());
        }
    }

    @Test
    @DisplayName("跨维护分支升级要标出来(2.13 → 2.18 改动比补丁版大)")
    void crossBranchIsFlagged() {
        List<Cve> hits = hitsFor(CveTable.GROUP_2X, "2.13.0");
        List<Remediation.Plan> plans = Remediation.plan(hits, art(CveTable.GROUP_2X, "2.13.0"));
        assertTrue(plans.get(0).crossBranch(), "2.13 → 2.18 是跨分支,必须提醒");
    }

    @Test
    @DisplayName("拿不到的修复版必须被标出来,不能印成升级建议")
    void unavailableFixIsFlagged() {
        // 旧 groupId 上的 3.x 规则:advisory 说升 3.1.4,而那个坐标根本没有 3.x。
        List<Cve> ghost = CveTable.all().stream()
                .filter(c -> c.groupId().equals(CveTable.GROUP_2X) && c.fixedIn().startsWith("3."))
                .toList();
        assertFalse(ghost.isEmpty());
        for (Cve c : ghost) {
            assertFalse(c.fixedAvailable(),
                    c.displayId() + " 的 " + c.fixedIn() + " 应被标为拿不到");
        }
    }
}
