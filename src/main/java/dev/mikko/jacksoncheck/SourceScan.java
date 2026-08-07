package dev.mikko.jacksoncheck;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 扫 {@code .java} 源码里的**触发条件标记**,给 11 条 advisory 做降噪。
 *
 * <p>这是本工具与「按版本匹配 advisory」的实质差别。Dependabot 只看版本,
 * 装了受影响版本就把 11 条全报;而这 11 条里绝大多数只在用了对应特性的代码里才成立
 * (@JsonView、多态类型、大小写不敏感匹配……),所以我们能回答那个真正有用的问题:
 * <b>「11 条里我真正中几条」</b>。
 *
 * <p>🔴 <b>只做文本匹配,不做 AST。</b>这是有意的取舍,不是偷懒:
 * 关键路径必须能被人读懂并自己核对 —— 一个看不懂的 AST 判定出错时没人能发现。
 * 代价写在下面这条里,报告里必须原样说出来:
 *
 * <p>🔴 <b>匹配不到 ≠ 安全。</b>三种情况会让「没找到」变成假的安心:
 * <ol>
 *   <li>你依赖的**第三方库**在它自己的代码里用了这些注解,而我们扫不到它的源码;
 *   <li>注解可能通过 mixin({@code ObjectMapper.addMixIn})或 {@code @JsonNaming}
 *       之类的运行时配置加上,源码里根本没有那个词;
 *   <li>你只是**没把源码目录传给我们**。
 * </ol>
 * 所以「未命中」在报告里的措辞永远是「未在你的源码里找到触发条件」,
 * 而不是「你不受影响」。
 */
public final class SourceScan {

    /** 构建产物目录:里面是源码的副本或生成代码,扫了会重复计数。 */
    private static final Set<String> SKIP_DIRS =
            Set.of("target", "build", "out", "bin", ".git", ".idea", "node_modules");

    /** 每个标记最多留几条证据。报告要能读,同时防止超大代码库把内存撑爆。 */
    private static final int MAX_EVIDENCE = 5;

    /** 单个文件大小上限,超过就跳过并告警(生成的巨型源文件不是我们要找的东西)。 */
    private static final long MAX_FILE_BYTES = 4L * 1024 * 1024;

    /**
     * 一处命中。
     *
     * @param file 文件路径
     * @param line 行号(从 1 开始)
     * @param text 该行内容(已裁剪)
     */
    public record Evidence(String file, int line, String text) {
        @Override
        public String toString() {
            return file + ":" + line + "  " + text;
        }
    }

    private final Map<String, List<Evidence>> hits = new LinkedHashMap<>();
    private final Map<String, Integer> counts = new LinkedHashMap<>();
    private final List<String> warnings = new ArrayList<>();
    private int filesScanned;

    /** 标记 → 证据(每个标记最多 {@value #MAX_EVIDENCE} 条)。 */
    public Map<String, List<Evidence>> hits() {
        return hits;
    }

    /** 标记 → 总命中次数(不受证据条数上限影响,报告里用它说明规模)。 */
    public Map<String, Integer> counts() {
        return counts;
    }

    public List<String> warnings() {
        return warnings;
    }

    public int filesScanned() {
        return filesScanned;
    }

    /** 扫到的源码里出现过 {@code ObjectMapper} —— 用来区分「没用 jackson」和「用了但没用这些特性」。 */
    public boolean usesJackson() {
        return counts.getOrDefault(Triggers.ANCHOR, 0) > 0;
    }

    public boolean hasMarker(String marker) {
        return counts.getOrDefault(marker, 0) > 0;
    }

    public void scan(Path target) throws IOException {
        if (!Files.exists(target)) {
            warnings.add("源码路径不存在:" + target);
            return;
        }
        if (Files.isRegularFile(target)) {
            scanFile(target);
            return;
        }
        try {
            Files.walkFileTree(target, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path d, BasicFileAttributes a) {
                    return SKIP_DIRS.contains(d.getFileName().toString().toLowerCase())
                            ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path f, BasicFileAttributes a) {
                    if (f.getFileName().toString().toLowerCase().endsWith(".java")) {
                        scanFile(f);
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path f, IOException e) {
                    warnings.add("无法访问 " + f + ":" + e.getMessage());
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    private void scanFile(Path f) {
        String src;
        try {
            if (Files.size(f) > MAX_FILE_BYTES) {
                warnings.add("跳过超大源文件(> " + (MAX_FILE_BYTES / 1024 / 1024) + "MB):" + f
                        + "(🔴 这不等于「它里面没有触发条件」)");
                return;
            }
            // 🔴 用 UTF-8 且**不抛异常**:中文注释里的 GBK 字节会让严格解码整个文件失败,
            //    而「一个文件解码失败」不该变成「这个项目没有触发条件」。
            src = new String(Files.readAllBytes(f), StandardCharsets.UTF_8);
        } catch (IOException e) {
            warnings.add("读取失败 " + f + ":" + e.getMessage()
                    + "(🔴 这不等于「它里面没有触发条件」)");
            return;
        }
        filesScanned++;
        String clean = stripComments(src);
        String[] lines = clean.split("\n", -1);
        String[] raw = src.split("\n", -1);

        for (Map.Entry<String, Pattern> e : Triggers.patterns().entrySet()) {
            Matcher m = e.getValue().matcher("");
            for (int i = 0; i < lines.length; i++) {
                m.reset(lines[i]);
                if (!m.find()) {
                    continue;
                }
                counts.merge(e.getKey(), 1, Integer::sum);
                List<Evidence> ev = hits.computeIfAbsent(e.getKey(), k -> new ArrayList<>());
                if (ev.size() < MAX_EVIDENCE) {
                    String t = (i < raw.length ? raw[i] : lines[i]).trim();
                    ev.add(new Evidence(f.toString(), i + 1, t.length() > 120 ? t.substring(0, 117) + "…" : t));
                }
            }
        }
    }

    /**
     * 把注释内容换成空格,<b>保留所有换行</b> —— 这样行号完全不变,证据才指得准。
     *
     * <p>🔴 <b>为什么非剥注释不可</b>:jackson 的用法几乎必然出现在示例注释和 Javadoc 里
     * ({@code // 例如 @JsonView(Public.class)}),不剥就是稳定的误报源,
     * 而误报会让「你真中 3 条」这个数字失去意义 —— 那正是本工具唯一的卖点。
     *
     * <p>🔴 <b>为什么必须认字符串</b>:URL 里的 {@code "https://…"} 带着 {@code //},
     * 不认字符串就会把那行剩下的部分当注释抹掉 —— 这是**漏报**方向的错,比误报更糟。
     * 文本块({@code """})单独处理成整块跳过,因为半个文本块会让状态机错位,
     * 而错位之后的漏报是静默的。
     */
    static String stripComments(String src) {
        // state[0] = 在块注释里;state[1] = 在文本块里。跨行,所以放在循环外。
        boolean[] state = new boolean[2];
        String[] lines = src.split("\n", -1);
        StringBuilder out = new StringBuilder(src.length());
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) {
                out.append('\n');
            }
            out.append(scrubLine(lines[i], state));
        }
        return out.toString();
    }

    /**
     * 处理一行,返回剥掉注释后的文本;{@code state} 是 {@code [inBlock, inText]},会被就地更新。
     */
    private static String scrubLine(String line, boolean[] state) {
        StringBuilder sb = new StringBuilder(line.length());
        int i = 0;
        boolean inStr = false;
        boolean inChar = false;
        while (i < line.length()) {
            char c = line.charAt(i);
            char next = i + 1 < line.length() ? line.charAt(i + 1) : '\0';

            if (state[0]) {                                   // 块注释里
                if (c == '*' && next == '/') {
                    state[0] = false;
                    sb.append("  ");
                    i += 2;
                } else {
                    sb.append(' ');
                    i++;
                }
                continue;
            }
            if (state[1]) {                                   // 文本块里
                if (c == '"' && next == '"' && i + 2 < line.length() && line.charAt(i + 2) == '"') {
                    state[1] = false;
                    sb.append("   ");
                    i += 3;
                } else {
                    sb.append(' ');
                    i++;
                }
                continue;
            }
            if (inStr) {
                sb.append(c);
                if (c == '\\') {                              // 转义,连吃两个
                    if (next != '\0') {
                        sb.append(next);
                        i++;
                    }
                } else if (c == '"') {
                    inStr = false;
                }
                i++;
                continue;
            }
            if (inChar) {
                sb.append(c);
                if (c == '\\') {
                    if (next != '\0') {
                        sb.append(next);
                        i++;
                    }
                } else if (c == '\'') {
                    inChar = false;
                }
                i++;
                continue;
            }
            // 普通代码
            if (c == '/' && next == '/') {
                while (i < line.length()) {                   // 整行剩余抹成空格
                    sb.append(' ');
                    i++;
                }
                continue;
            }
            if (c == '/' && next == '*') {
                state[0] = true;
                sb.append("  ");
                i += 2;
                continue;
            }
            if (c == '"' && next == '"' && i + 2 < line.length() && line.charAt(i + 2) == '"') {
                state[1] = true;
                sb.append("   ");
                i += 3;
                continue;
            }
            if (c == '"') {
                inStr = true;
            } else if (c == '\'') {
                inChar = true;
            }
            sb.append(c);
            i++;
        }
        return sb.toString();
    }
}
