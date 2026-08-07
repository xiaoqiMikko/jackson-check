package dev.mikko.jacksoncheck;

import java.util.List;

/**
 * 一条 advisory 在**一个 groupId 的一条维护分支**上的判定规则。由 tools/gen_rules.py 生成。
 *
 * <p>🔴 <b>粒度是「advisory × groupId × 版本区间」而不是「CVE」</b> —— 这是本工具存在的理由之一。
 * Jackson 3 换了 groupId({@code com.fasterxml.jackson.core} → {@code tools.jackson.core}),
 * 而 2.x 侧同时维护着 2.18 / 2.21 / 2.22 三条分支,同一条 advisory 在每条分支上的
 * 受影响区间和修复版都不一样,甚至<b>跨条目还不一致</b>:
 * 大多数条目说升 2.21.4,而 CVE-2026-54515、CVE-2026-59889 和 GHSA-mhm7-754m-9p8w 要 2.21.5。
 * 压成一条「jackson-databind &lt; 2.21.4 有洞」就是替用户做错了判断。
 */
public record Cve(
        /** GHSA 编号。本批有一条没有 CVE 号,所以主键用 GHSA 而不是 CVE。 */
        String ghsaId,
        /** CVE 编号;GHSA-mhm7-754m-9p8w 没有,此时为空串 */
        String cveId,
        /** 受影响坐标的 groupId:{@code com.fasterxml.jackson.core}(2.x)或 {@code tools.jackson.core}(3.x) */
        String groupId,
        /** GitHub advisory 评级:low / medium / high / critical */
        String severity,
        /** CVSS v3 分数;-1 表示未给出 */
        double cvss,
        /** 这条规则属于哪条维护分支,如 "2.18" / "2.21" / "3.1"。求交集时按它分组。 */
        String branch,
        /** 受影响下限;空表示不设下限 */
        String low,
        /** 下限是否含端点 */
        boolean lowIncl,
        /** 受影响上限;空表示不设上限 */
        String high,
        /** 上限是否含端点 */
        boolean highIncl,
        /** 修复版本(升到它或更高即可覆盖本条) */
        String fixedIn,
        /**
         * 这个修复版本在 Maven Central 上**拿得到吗**。
         *
         * <p>🔴 实测有两个方向相反的幽灵:advisory 在 {@code com.fasterxml.jackson.core}
         * 上挂了 3.x 区间(修复版 3.1.4),在 {@code tools.jackson.core} 上挂了 2.x 区间
         * (修复版 2.21.4)—— 而 Central 上前者只发过 2.x、后者只发过 3.x,
         * 这两个 jar 都是 <b>HTTP 404</b>。
         * <b>把一个升不了的版本印成升级建议,不是「误报」,是让用户去做一件做不成的事</b>,
         * 所以必须标出来。
         */
        boolean fixedAvailable,
        /**
         * 触发条件分类,如 JSONVIEW / POLYMORPHIC / CASE_INSENSITIVE。
         *
         * <p>11 条分成 10 类 —— 这就是降噪的余地:Dependabot 只看版本会把 11 条全报,
         * 而多数条目只在用了对应特性的代码里才成立。
         */
        String condKind,
        /** 触发条件说明,逐条对照官方描述原文,未作外推 */
        String condText,
        /**
         * 判定这条是否触发要在源码里找的标记(全部命中 = 条件成立)。
         *
         * <p>🔴 <b>空集合表示无条件</b>,但本批 11 条一条都没有 —— 每条都有条件,
         * 这正是降噪能做实的前提。
         */
        List<String> markers,
        /** 标题(GitHub advisory 的 summary 原文) */
        String title,
        /** 描述原文的第一句(英文原句,非转述) */
        String desc) {

    /** 报告里显示的编号:有 CVE 号用 CVE 号,没有就用 GHSA 号。 */
    public String displayId() {
        return cveId.isEmpty() ? ghsaId : cveId;
    }

    /** 区间文本,照 advisory 的开闭端点渲染,不做换算。 */
    public String rangeText() {
        StringBuilder sb = new StringBuilder();
        if (low != null && !low.isEmpty()) {
            sb.append(low).append(lowIncl ? " <= " : " < ");
        }
        sb.append("版本");
        if (high != null && !high.isEmpty()) {
            sb.append(highIncl ? " <= " : " < ").append(high);
        }
        return sb.toString();
    }
}
