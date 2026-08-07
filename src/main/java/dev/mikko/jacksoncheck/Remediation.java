package dev.mikko.jacksoncheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 逐条求交集,算出「盖住你命中的全部条目的那个版本」。
 *
 * <p>🔴 <b>这是本工具最硬的一块。</b>2026 年这批 11 条 advisory 里,
 * 出现最多的修复版是 <b>3.1.4 / 2.21.4 / 2.18.8</b> —— 8 条都这么写。
 * 但另外三条要求更高:
 * <ul>
 *   <li>CVE-2026-54515 → 2.18.9 / 2.21.5 / 2.22.1
 *   <li>CVE-2026-59889 → 2.18.9 / 2.21.5 / 3.1.5
 *   <li><b>GHSA-mhm7-754m-9p8w(没有 CVE 号)</b> → 2.18.9 / 2.21.5
 * </ul>
 * 最后一条的 advisory 原文自己写着:
 * <i>「the fix was never backported to 2.21 or 2.18 … Users on 2.21.4 and 2.18.8
 * who upgraded per the published advisories remain vulnerable」</i>。
 *
 * <p>也就是说,<b>照着单条 advisory 升到 2.21.4 的人,以为修完了,实际还中三条</b>,
 * 其中一条连 CVE 号都没有,搜不到。求交集就是为了回答这个问题:
 * 我到底该升到哪个版本才一次到位。
 *
 * <p>算法本身刻意做得简单到能被人核对:<b>把命中条目的修复版按「大版本线」分组,取最大值。</b>
 * 不做跨大版本线的比较 —— 2.x 用户不该被推去升 3.x(那是换 groupId 的破坏性升级)。
 */
public final class Remediation {

    /**
     * @param groupId    该升哪个坐标
     * @param target     目标版本
     * @param available  这个版本在 Maven Central 上拿不拿得到
     * @param current    你现在的版本
     * @param crossBranch 目标版本是不是跨了维护分支(如 2.13 → 2.18),升级风险更大
     * @param covers     升到它能盖住的条目编号
     * @param drivenBy   把目标顶到这么高的那条(即「照单条 advisory 升级会漏的那条」)
     */
    public record Plan(String groupId, String target, boolean available, JacksonVersion current,
                       boolean crossBranch, List<String> covers, String drivenBy) {
    }

    /**
     * 按坐标 + 大版本线求交集。
     *
     * @param hits 版本命中的规则(触发条件是否成立不影响升级目标 —— 装了受影响版本就该升)
     */
    public static List<Plan> plan(List<Cve> hits, List<Scanner.Artifact> scanned) {
        // key = groupId + "|" + 大版本线,例如 "com.fasterxml.jackson.core|2"
        Map<String, List<Cve>> byLine = new LinkedHashMap<>();
        for (Cve c : hits) {
            String line = c.fixedIn().isEmpty() ? "?" : c.fixedIn().split("\\.")[0];
            byLine.computeIfAbsent(c.groupId() + "|" + line, k -> new ArrayList<>()).add(c);
        }

        List<Plan> plans = new ArrayList<>();
        for (Map.Entry<String, List<Cve>> e : byLine.entrySet()) {
            String group = e.getKey().substring(0, e.getKey().indexOf('|'));
            Cve top = null;
            for (Cve c : e.getValue()) {
                if (c.fixedIn().isEmpty()) {
                    continue;
                }
                if (top == null || newer(c.fixedIn(), top.fixedIn())) {
                    top = c;
                }
            }
            if (top == null) {
                continue;
            }
            // 你当前装的、属于这个坐标的版本(取最低的那份 —— 它是短板)
            JacksonVersion current = null;
            for (Scanner.Artifact a : scanned) {
                if (a.groupId().equals(group)
                        && (current == null || a.version().compareTo(current) < 0)) {
                    current = a.version();
                }
            }
            JacksonVersion tv = JacksonVersion.parse(top.fixedIn());
            boolean cross = current != null && tv != null && !current.branch().equals(tv.branch());
            List<String> covers = new ArrayList<>();
            for (Cve c : e.getValue()) {
                if (!covers.contains(c.displayId())) {
                    covers.add(c.displayId());
                }
            }
            plans.add(new Plan(group, top.fixedIn(), top.fixedAvailable(), current, cross,
                    covers, top.displayId()));
        }
        return plans;
    }

    /**
     * 找出「照单条 advisory 升级会漏的那几条」—— 即修复版严格高于同一坐标同一大版本线
     * 上最低修复版的条目。这是文章和报告里的承重数字,单独抽成方法以便单独测。
     */
    public static List<Cve> beyondLowestFix(List<Cve> hits) {
        Map<String, String> lowest = new LinkedHashMap<>();
        for (Cve c : hits) {
            if (c.fixedIn().isEmpty()) {
                continue;
            }
            String k = c.groupId() + "|" + c.fixedIn().split("\\.")[0];
            String cur = lowest.get(k);
            if (cur == null || newer(cur, c.fixedIn())) {
                lowest.put(k, c.fixedIn());
            }
        }
        List<Cve> out = new ArrayList<>();
        for (Cve c : hits) {
            if (c.fixedIn().isEmpty()) {
                continue;
            }
            String k = c.groupId() + "|" + c.fixedIn().split("\\.")[0];
            if (newer(c.fixedIn(), lowest.get(k))) {
                out.add(c);
            }
        }
        return out;
    }

    /** a 是否严格新于 b。解析不了的一律返回 false —— 宁可不给建议,也不给错建议。 */
    private static boolean newer(String a, String b) {
        JacksonVersion va = JacksonVersion.parse(a);
        JacksonVersion vb = JacksonVersion.parse(b);
        return va != null && vb != null && va.compareTo(vb) > 0;
    }

    private Remediation() {
    }
}
