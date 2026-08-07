package dev.mikko.jacksoncheck;

import java.util.ArrayList;
import java.util.List;

/**
 * 判断一条规则对**这次扫到的这套东西**适不适用。分两步,两步都可能出错,方向不同:
 *
 * <ol>
 *   <li><b>版本判定</b>(硬判据)—— 扫到的构件坐标 + 版本落不落在受影响区间里。
 *       这一步 Dependabot 也做,且做得准。
 *   <li><b>触发条件判定</b>(降噪)—— 你的源码里有没有那条 advisory 需要的特性。
 *       这一步是本工具存在的理由,也是唯一可能给出「11 条里你真中 3 条」的地方。
 * </ol>
 *
 * <p>🔴 <b>两步的错误代价不对称,所以处理方式也不对称:</b>
 * 版本判定漏了 → 真有风险却不报,而不报警长得和「你很安全」一模一样;
 * 触发条件判定漏了 → 只是没降下噪,用户仍会看到那一条。
 * 因此<b>条件判定永远只降级不排除</b>:未命中的条目仍然完整列出,只是标成
 * {@link Kind#VERSION_HIT_NO_TRIGGER},绝不从报告里消失。
 */
public final class Applicability {

    public enum Kind {
        /** 版本中 + 触发条件的标记全部在源码里找到 —— 最该先修的。 */
        HIT,
        /** 版本中 + 只找到部分标记 —— 可能成立,要人看一眼。 */
        HIT_PARTIAL,
        /**
         * 版本中,但一个触发条件标记都没找到。
         *
         * <p>🔴 <b>这不等于安全</b>:第三方库可能在它自己的代码里用了这些注解,
         * 而我们扫不到它的源码;也可能你根本没把源码目录传进来。
         */
        VERSION_HIT_NO_TRIGGER,
        /**
         * 版本中,但这次<b>根本没扫源码</b>,所以降噪没做。
         *
         * <p>🔴 必须和 {@link #HIT_PARTIAL} 分开:真实构件复验时发现,
         * 扫一个 fat jar(里面没有 .java)会把命中的条目全印成「触发条件部分成立」——
         * 那句话是**假的**,我们根本没看过任何源码。
         * 「没做判断」和「判断结果是一半」长得像,含义完全不同。
         */
        NO_SOURCE_SCAN,
        /** 装了这个坐标,但版本不在受影响区间内。 */
        VERSION_SAFE,
        /** 没扫到这条规则针对的坐标(比如你只用 2.x,而这条挂在 3.x 坐标上)。 */
        NOT_PRESENT
    }

    /**
     * @param kind      判定结果
     * @param version   参与判定的版本;NOT_PRESENT 时为 null
     * @param where     该构件在哪个文件里;NOT_PRESENT 时为空串
     * @param found     在源码里找到的标记
     * @param missing   没找到的标记
     * @param reason    非命中时的说明
     */
    public record Verdict(Kind kind, JacksonVersion version, String where,
                          List<String> found, List<String> missing, String reason) {

        /** 版本落在受影响区间内(不论触发条件如何)—— Dependabot 会报的就是这一档。 */
        public boolean versionHit() {
            return kind == Kind.HIT || kind == Kind.HIT_PARTIAL
                    || kind == Kind.VERSION_HIT_NO_TRIGGER || kind == Kind.NO_SOURCE_SCAN;
        }

        /**
         * 触发条件全部或部分成立 —— 这才是「你真中的」。
         *
         * <p>🔴 {@link Kind#NO_SOURCE_SCAN} <b>不算</b>:没扫源码时我们没有任何依据说它触发了。
         * 但它仍是 {@link #versionHit()},所以既不会消失,也不会被冒充成一个我们没做过的判断。
         */
        public boolean triggered() {
            return kind == Kind.HIT || kind == Kind.HIT_PARTIAL;
        }
    }

    /**
     * @param cve      一条规则(已是 advisory × groupId × 区间 粒度)
     * @param scanned  扫到的构件
     * @param src      源码扫描结果;为 null 表示这次没扫源码(此时不做降噪,一律按版本判)
     */
    public static Verdict judge(Cve cve, List<Scanner.Artifact> scanned, SourceScan src) {
        // 第一步:版本。同一个 groupId 可能扫到多份(fat jar 里一份、WEB-INF/lib 里又一份)。
        // 🔴 **任一份命中即命中** —— 挑其中一份来判会漏:老 WAR 里塞着两代 jar 时,
        //    拿新的那份判成安全,而老的那份明明中。
        Scanner.Artifact hit = null;
        Scanner.Artifact anySameGroup = null;
        for (Scanner.Artifact a : scanned) {
            if (!a.groupId().equals(cve.groupId())) {
                continue;
            }
            anySameGroup = anySameGroup == null ? a : anySameGroup;
            if (a.version().inRange(cve.low(), cve.lowIncl(), cve.high(), cve.highIncl())) {
                hit = a;
                break;
            }
        }
        if (hit == null) {
            if (anySameGroup == null) {
                return new Verdict(Kind.NOT_PRESENT, null, "", List.of(), List.of(),
                        "未扫到 " + cve.groupId() + ":" + CveTable.ARTIFACT);
            }
            return new Verdict(Kind.VERSION_SAFE, anySameGroup.version(), anySameGroup.path(),
                    List.of(), List.of(),
                    "版本 " + anySameGroup.version() + " 不在受影响区间(" + cve.rangeText() + ")内");
        }

        // 第二步:触发条件降噪。
        List<String> found = new ArrayList<>();
        List<String> missing = new ArrayList<>();
        if (src == null) {
            return new Verdict(Kind.NO_SOURCE_SCAN, hit.version(), hit.path(), found, missing,
                    "本次未扫描源码,降噪这一步没做 —— 不是「部分成立」,是没有依据");
        }
        for (String m : cve.markers()) {
            (src.hasMarker(m) ? found : missing).add(m);
        }
        if (missing.isEmpty()) {
            return new Verdict(Kind.HIT, hit.version(), hit.path(), found, missing, "");
        }
        if (!found.isEmpty()) {
            return new Verdict(Kind.HIT_PARTIAL, hit.version(), hit.path(), found, missing,
                    "找到 " + found.size() + "/" + cve.markers().size() + " 个触发条件标记");
        }
        return new Verdict(Kind.VERSION_HIT_NO_TRIGGER, hit.version(), hit.path(), found, missing,
                "未在你的源码里找到触发条件(" + String.join("、", cve.markers()) + ")"
                        + " —— 🔴 这不等于安全,见报告末尾说明");
    }

    private Applicability() {
    }
}
