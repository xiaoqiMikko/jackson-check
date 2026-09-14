package dev.mikko.jacksoncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 判定表是生成的,但生成对不对要在 Java 这一侧再钉一遍 ——
 * gen_rules.py 的断言防的是「源变了没发现」,这里的测试防的是「生成的东西没落到 Java 里」。
 * 两者查的不是同一件事:第 8 注就出现过生成脚本全绿而 Java 侧拿到空表的形状。
 */
class CveTableTest {

    @Test
    @DisplayName("判定表不能是空壳")
    void tableIsNotEmpty() {
        assertTrue(CveTable.all().size() >= 30,
                "只有 " + CveTable.all().size() + " 条规则 —— 生成八成失败了");
        // 08-07 首版是 11 条;08-21 / 09-01 又发了 4 条(v0.2.0,2026-09-14)
        assertEquals(15, CveTable.OFFICIAL_TOTAL, "2026 年这批截至 09-14 是 15 条");
    }

    @Test
    @DisplayName("🔴 两个 groupId 必须都覆盖 —— 只做 2.x 的工具对 Jackson 3 用户完全无效")
    void bothGroupIdsCovered() {
        Set<String> groups = CveTable.all().stream().map(Cve::groupId).collect(Collectors.toSet());
        assertTrue(groups.contains(CveTable.GROUP_2X), "缺 2.x 坐标");
        assertTrue(groups.contains(CveTable.GROUP_3X), "缺 3.x 坐标(Jackson 3 换了 groupId)");
    }

    @Test
    @DisplayName("每条规则都要有触发条件,不许留空")
    void everyRuleHasCondition() {
        for (Cve c : CveTable.all()) {
            assertFalse(c.condKind().isEmpty(), c.displayId() + " 缺触发条件分类");
            assertFalse(c.condText().isEmpty(), c.displayId() + " 缺触发条件说明");
            assertFalse(c.markers().isEmpty(),
                    c.displayId() + " 没有源码标记 —— 它就降不了噪,只会退化成版本检测器");
        }
    }

    @Test
    @DisplayName("触发条件必须有区分度,否则降噪等于没做")
    void conditionsAreDiverse() {
        Set<String> kinds = CveTable.all().stream().map(Cve::condKind).collect(Collectors.toSet());
        assertTrue(kinds.size() >= 6, "只有 " + kinds.size() + " 种触发条件,降噪没有区分度");
    }

    @Test
    @DisplayName("所有源码标记都必须在 Triggers 表里有对应的正则")
    void allMarkersAreDefined() {
        for (Cve c : CveTable.all()) {
            for (String m : c.markers()) {
                assertTrue(Triggers.patterns().containsKey(m),
                        c.displayId() + " 用了未定义的标记 " + m + " —— 它永远不会命中,是静默漏报");
            }
        }
    }

    @Test
    @DisplayName("🔴 幽灵坐标:确实存在拿不到的修复版,且是双向的")
    void ghostCoordinatesExist() {
        List<Cve> ghosts = CveTable.all().stream()
                .filter(c -> !c.fixedIn().isEmpty() && !c.fixedAvailable()).toList();
        assertFalse(ghosts.isEmpty(), "「幽灵坐标」这个核心主张不成立了,文案要改");
        // 方向一:旧 groupId 上挂着 3.x
        assertTrue(ghosts.stream().anyMatch(
                        c -> c.groupId().equals(CveTable.GROUP_2X) && c.fixedIn().startsWith("3.")),
                "旧坐标上应有 3.x 幽灵");
        // 方向二:新 groupId 上挂着 2.x
        assertTrue(ghosts.stream().anyMatch(
                        c -> c.groupId().equals(CveTable.GROUP_3X) && c.fixedIn().startsWith("2.")),
                "新坐标上应有 2.x 幽灵");
    }

    @Test
    @DisplayName("有一条没有 CVE 号 —— 报告必须能用 GHSA 号显示它")
    void oneEntryHasNoCve() {
        List<Cve> noCve = CveTable.all().stream().filter(c -> c.cveId().isEmpty()).toList();
        assertFalse(noCve.isEmpty(), "GHSA-mhm7-754m-9p8w 没有 CVE 号,它是本注最硬的那条");
        for (Cve c : noCve) {
            assertTrue(c.displayId().startsWith("GHSA-"), "没有 CVE 号时要退回 GHSA 号显示");
        }
    }

    @Test
    @DisplayName("🔴 Dependabot 盲区数是查了两个源得出的:08-07 为 0,09-14 为 4")
    void blindSpotIsMeasuredNotAssumed() {
        // 数字本身会变(GitHub 收录后会回到 0),重要的是它有来源:
        // gen_rules.py 的 ASSERT2 每次重跑都会逐个按 GHSA 号去全局库复核。
        assertEquals(4, CveTable.DEPENDABOT_BLIND);
        Set<String> blind = CveTable.all().stream().filter(c -> !c.inGlobalDb())
                .map(Cve::ghsaId).collect(Collectors.toSet());
        assertEquals(Set.of("GHSA-q4xh-88c3-wmh7", "GHSA-wjgm-6hv5-3cvf",
                "GHSA-vvgp-rfg2-7rr6", "GHSA-gx83-3vf8-gh7j"), blind,
                "盲区必须正好是 08-21 / 09-01 那 4 条 —— 常数和逐条标记要对得上");
    }

    @Test
    @DisplayName("🔴 advisory 修复版笔误被纠正:77310 在 2.22 线写的 2.21.1 比区间下限还低")
    void typoFixVersionCorrected() {
        List<Cve> rows = CveTable.all().stream()
                .filter(c -> c.ghsaId().equals("GHSA-vvgp-rfg2-7rr6"))
                .filter(c -> c.groupId().equals(CveTable.GROUP_2X) && "2.22.0".equals(c.low()))
                .toList();
        assertEquals(1, rows.size());
        assertEquals("2.22.1", rows.get(0).fixedIn(), "照抄 2.21.1 会让 2.22.0 用户去「升」到更低的版本");
    }

    @Test
    @DisplayName("同一条 advisory 在同一坐标上不能有重复区间")
    void noDuplicateRules() {
        Set<String> seen = new HashSet<>();
        for (Cve c : CveTable.all()) {
            String k = c.ghsaId() + "|" + c.groupId() + "|" + c.low() + "|" + c.high();
            assertTrue(seen.add(k), "重复规则:" + k + " —— 会让报告里同一条出现两次");
        }
    }
}
