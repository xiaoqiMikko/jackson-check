package dev.mikko.jacksoncheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * jackson-databind 版本号解析与比较。
 *
 * <p>🔴 <b>jackson 的版本号有四段的</b> —— 补丁线上会出现 {@code 2.9.10.8}、{@code 2.12.7.1}
 * 这种第四段,而绝大多数「按 x.y.z 解析」的实现会在这里直接崩掉或把它截成 2.9.10。
 * 截断的后果是方向错的:{@code 2.9.10.8} 被当成 {@code 2.9.10} 去比区间,
 * 而这两个版本正好分处若干条 advisory 的分界线两侧。
 *
 * <p>🔴 <b>限定符只认 jackson 真实用过的那几个</b>,别放宽成 {@code [A-Za-z]+} ——
 * 那样 {@code 2.18.x} 这种通配写法也会被「成功」解析成某个预发布版,
 * 于是区间判定拿它去比较,<b>结果既不报错也不正确</b>(第 6 注 tomcat-check 踩过)。
 * 解析不了就返回 null,让调用方显式处理。
 *
 * <p>排序:同数字段时 <b>预发布排在正式版前面</b>,即 {@code 3.0.0-rc1 < 3.0.0}。
 */
public final class JacksonVersion implements Comparable<JacksonVersion> {

    private static final Pattern P = Pattern.compile(
            "^(\\d+(?:\\.\\d+)*)"                            // 数字段,段数不限(jackson 有四段)
            + "(?:[.\\-_]?(alpha|beta|rc|milestone|m|pr)"    // 限定符(可无分隔符)
            + "[.\\-_]?(\\d*))?$",                           // 限定符序号(可缺省)
            Pattern.CASE_INSENSITIVE);

    /** 限定符排序权。正式版用 {@link #RELEASE},排在所有预发布之后。 */
    private static final int RELEASE = 100;

    private static int qualRank(String q) {
        return switch (q.toLowerCase(Locale.ROOT)) {
            case "milestone", "m" -> 1;
            case "alpha" -> 2;
            case "beta" -> 3;
            case "rc", "pr" -> 4;
            default -> RELEASE;
        };
    }

    private final List<Integer> nums;
    private final int qual;
    private final int qualOrd;
    private final String raw;

    private JacksonVersion(List<Integer> nums, int qual, int qualOrd, String raw) {
        this.nums = nums;
        this.qual = qual;
        this.qualOrd = qualOrd;
        this.raw = raw;
    }

    /** 解析失败返回 null —— 调用方必须处理,不要用「解析不出就当 0」蒙混过去。 */
    public static JacksonVersion parse(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        if (t.isEmpty()) {
            return null;
        }
        Matcher m = P.matcher(t);
        if (!m.matches()) {
            return null;
        }
        List<Integer> ns = new ArrayList<>();
        for (String part : m.group(1).split("\\.")) {
            try {
                ns.add(Integer.parseInt(part));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        int q = RELEASE;
        int ord = 0;
        if (m.group(2) != null) {
            q = qualRank(m.group(2));
            String d = m.group(3);
            ord = (d == null || d.isEmpty()) ? 0 : Integer.parseInt(d);
        }
        return new JacksonVersion(ns, q, ord, t);
    }

    /** 大版本线:2.18.8 → 2;3.1.4 → 3。用于判断该用哪个 groupId。 */
    public int major() {
        return nums.get(0);
    }

    /** 维护分支:2.18.8 → "2.18";3.1.4 → "3.1"。求交集时按分支分组。 */
    public String branch() {
        return nums.size() >= 2 ? nums.get(0) + "." + nums.get(1) : nums.get(0) + ".0";
    }

    @Override
    public int compareTo(JacksonVersion o) {
        int n = Math.max(nums.size(), o.nums.size());
        for (int i = 0; i < n; i++) {
            // 🔴 2.18 与 2.18.0 必须相等,且 2.18.8 < 2.18.8.1:
            //    缺省段补 0,四段版本才能和三段版本正确比较。
            int a = i < nums.size() ? nums.get(i) : 0;
            int b = i < o.nums.size() ? o.nums.get(i) : 0;
            if (a != b) {
                return Integer.compare(a, b);
            }
        }
        if (qual != o.qual) {
            return Integer.compare(qual, o.qual);
        }
        return Integer.compare(qualOrd, o.qualOrd);
    }

    /**
     * 区间判定,端点是否包含由调用方给出。
     *
     * <p>🔴 <b>端点开闭直接照抄 advisory 原文,不做「上限 +1」的转换</b>:
     * 同一批 advisory 里 {@code < 2.18.8} 和 {@code <= 2.18.7} 两种写法都有,
     * 第 6 注 tomcat-check 就是在做这种换算时错位过一格 —— 而错位一格的判定表看起来完全正常。
     * 少一次换算 = 少一个能静默出错的地方。
     *
     * @param low      下限,空表示不设限
     * @param lowIncl  下限是否含端点
     * @param high     上限,空表示不设限
     * @param highIncl 上限是否含端点
     */
    public boolean inRange(String low, boolean lowIncl, String high, boolean highIncl) {
        if (low != null && !low.isEmpty()) {
            JacksonVersion lo = parse(low);
            if (lo == null) {
                return false;
            }
            int c = compareTo(lo);
            if (c < 0 || (c == 0 && !lowIncl)) {
                return false;
            }
        }
        if (high != null && !high.isEmpty()) {
            JacksonVersion hi = parse(high);
            if (hi == null) {
                return false;
            }
            int c = compareTo(hi);
            if (c > 0 || (c == 0 && !highIncl)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof JacksonVersion v && compareTo(v) == 0;
    }

    @Override
    public int hashCode() {
        return nums.get(0);
    }

    @Override
    public String toString() {
        return raw;
    }
}
