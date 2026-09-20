package dev.mikko.jacksoncheck;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 扫描构建产物,找出实际装了哪些 jackson-databind 及其 <b>groupId</b> 与版本。
 *
 * <p>🔴 <b>为什么 groupId 必须扫出来而不能假设</b> —— Jackson 3 换了坐标:
 * {@code com.fasterxml.jackson.core:jackson-databind}(2.x)→
 * {@code tools.jackson.core:jackson-databind}(3.x)。
 * 两个坐标的 artifactId 一模一样,jar 文件名也一模一样({@code jackson-databind-<版本>.jar}),
 * 只有 {@code META-INF} 里才分得清。而 advisory 在这两个坐标之间贴串了版本区间
 * (见 {@link Cve#fixedAvailable()}),所以判定必须认准坐标,不能只看版本号。
 *
 * <p>🔴 <b>为什么必须扫产物而不是读 pom</b> —— shade / uber jar 会把 jackson 的类
 * 直接打进自己的 jar(甚至改包名重定位),依赖坐标层面完全看不见,
 * 但 {@code maven-shade-plugin} 默认保留 {@code META-INF/maven/**},
 * 所以扫实物能把这层看穿,读 pom 不能。
 *
 * <p>能认三种形态:普通 jar、Spring Boot fat jar({@code BOOT-INF/lib/})、
 * 传统 WAR({@code WEB-INF/lib/});以及上述三种被 shade 进同一个归档的情形。
 */
public final class Scanner {

    /** 递归展开深度上限。fat jar 内的 jar 一般不再套 jar,留 2 层足够且防病态归档。 */
    private static final int MAX_DEPTH = 2;

    /**
     * 要扫的 artifactId —— v0.3.0 起是两个。
     *
     * <p>🔴 <b>v0.2.x 这里写死了一个 jackson-databind,于是 jackson-core 的洞一条都扫不出来</b>,
     * 而扫描器不会因此报任何错:它只是安静地跳过所有 jackson-core-*.jar。
     * <b>「没扫到」和「没有」在报告里长得一模一样。</b>
     */
    static final String[] ARTIFACTS = CveTable.ARTIFACTS;

    /** 路径是不是某个 jackson 坐标的 pom.properties(两个 group × 两个 artifact)。 */
    private static boolean isPomProps(String lower) {
        for (String g : new String[]{CveTable.GROUP_2X, CveTable.GROUP_3X}) {
            for (String a : ARTIFACTS) {
                if (lower.endsWith("meta-inf/maven/" + g + "/" + a + "/pom.properties")) {
                    return true;
                }
            }
        }
        return false;
    }

    /** {@code <artifact>-<版本>.jar};两个 artifact 都认,group(1)=artifactId、group(2)=版本。 */
    private static final Pattern NAME_VER =
            Pattern.compile("^(jackson-databind|jackson-core)-(\\d[\\w.\\-]*)\\.jar$",
                    Pattern.CASE_INSENSITIVE);

    /**
     * 扫到的一份 jackson 构件(v0.3.0 起可能是 jackson-databind,也可能是 jackson-core)。
     *
     * @param path    它在哪(fat jar 内的用 {@code !/} 分隔)
     * @param groupId 坐标的 groupId —— 2.x 与 3.x 不同,判定时必须区分
     * @param artifactId 坐标的 artifactId —— {@code jackson-databind} 或 {@code jackson-core};
     *                   🔴 两者<b>各自独立发版</b>,升了一个不代表另一个也升了
     * @param version 版本
     * @param source  坐标与版本取自哪里:pom.properties / MANIFEST / 文件名
     * @param guessedGroup groupId 是不是**按大版本推断**出来的(而非从元数据直接读到)
     */
    public record Artifact(String path, String groupId, String artifactId, JacksonVersion version,
                           String source, boolean guessedGroup) {

        /** 完整坐标,判定与求交集都以它为键。 */
        public String coord() {
            return groupId + ":" + artifactId;
        }
    }

    private final List<Artifact> found = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

    /**
     * 构件里注册的 {@code java.nio.file.spi.FileSystemProvider}(v0.2.0 加,给 CVE-2026-19032 用)。
     *
     * <p>🔴 advisory 原文:只有 JDK 自带 provider(file、jar/zipfs)时,Path 反序列化的结果是无害的;
     * 要产生挂载、网络 I/O 等副作用,<b>classpath 上必须有第三方 provider</b>。
     * JDK 自带的 provider 在 JDK 模块里,不在任何 jar 中 —— 所以扫构件时找到的一律是第三方的。
     * <p>⚠️ 只看得见你传进来的构件;运行时由容器 / agent 额外加进 classpath 的看不见。
     */
    private final List<String> fsProviders = new ArrayList<>();

    /** 扫到的第三方 FileSystemProvider,形如「类名  (所在 jar)」。 */
    public List<String> fileSystemProviders() {
        return fsProviders;
    }

    /**
     * 有多少个文件是「读不动」的(不是 zip / 截断 / IO 失败)。
     *
     * <p>🔴 它存在的理由是退出码:留痕是给人看的,而 CI 与脚本看的是退出码 ——
     * 少了它,「我没能读它」在自动化里等于「通过」(2026-09-09 加)。
     * <p>🔴 用计数器而不是去匹配告警文案:文案改一个字,匹配式判据就安静失效了。
     */
    private int unreadable;

    /** 读不动的文件数 —— 大于 0 时退出码不许是 0。 */
    public int unreadableCount() {
        return unreadable;
    }


    public List<Artifact> artifacts() {
        return found;
    }

    public List<String> warnings() {
        return warnings;
    }

    public void scan(Path target) throws IOException {
        if (!Files.exists(target)) {
            warnings.add("路径不存在:" + target);
            return;
        }
        if (Files.isDirectory(target)) {
            Files.walkFileTree(target, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path f, BasicFileAttributes a) {
                    String n = f.getFileName().toString().toLowerCase();
                    if (n.endsWith(".jar") || n.endsWith(".war") || n.endsWith(".ear")) {
                        try {
                            scanArchive(f.toString(), Files.readAllBytes(f), 0);
                        } catch (IOException e) {
                            unreadable++;
            warnings.add("读取失败 " + f + ":" + e.getMessage());
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path f, IOException e) {
                    warnings.add("无法访问 " + f + ":" + e.getMessage());
                    return FileVisitResult.CONTINUE;
                }
            });
        } else {
            scanArchive(target.toString(), Files.readAllBytes(target), 0);
        }
    }

    /**
     * ☠️ <b>ZipInputStream 对非 zip 内容不抛异常,只是一个条目都不给</b>(2026-09-08 实测)。
     *
     * <p>后果:一个损坏 / 加密 / 根本不是 zip 的 .jar 会静默走完扫描,得出「没扫到 jackson」——
     * 而用户会把它读成「我不受影响」。<b>「读不动」和「你是安全的」必须是两句话。</b>
     *
     * <p>🔴 这个坑第 10 注(log4j-check)早就实测记过并在那一注里加了防线,
     * 但后续各注的扫描代码是从别处复制来的,<b>防线没有跟着传下来</b> ——
     * 2026-09-08 第 24 注的真 jar 端到端回测把它重新撞出来,逐个实测发现 10 个已上线工具都有。
     *
     * <p>空 zip 的魔数是 {@code PK\05\06},它合法且真的没有条目,必须与「不是 zip」分开,
     * 否则每个空 jar 都会变成一条假告警。
     */
    static boolean looksLikeZip(byte[] b) {
        if (b == null || b.length < 4 || b[0] != 'P' || b[1] != 'K') return false;
        int c = b[2], d = b[3];
        return (c == 3 && d == 4) || (c == 5 && d == 6) || (c == 7 && d == 8);
    }


    /**
     * 是不是一个<b>合法的空 zip</b> —— 整个文件就是一条 22 字节的 EOCD 记录。
     *
     * <p>🔴 判据不是「魔数像 zip」:一个 PK 03 04 开头但截断的文件魔数也是对的。
     * 空 zip 是真的空,不该报错;截断的必须报。
     */
    static boolean isEmptyZip(byte[] b) {
        return b != null && b.length == 22
                && b[0] == 'P' && b[1] == 'K' && b[2] == 5 && b[3] == 6;
    }

    private void scanArchive(String path, byte[] bytes, int depth) {
        if (!looksLikeZip(bytes)) {
            unreadable++;
            warnings.add("这个文件读不动,不是有效的 zip/jar:" + path
                    + "(可能是截断、加密,或其实是个 HTML 错误页)"
                    + " —— 🔴 **这不等于「里面没有 jackson」**");
            return;
        }

        List<byte[]> innerBytes = new ArrayList<>();
        List<String> innerPaths = new ArrayList<>();
        List<String> coords = new ArrayList<>();
        String mfSymbolic = null;
        String mfVersion = null;

        int entries = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                entries++;
                if (e.isDirectory()) {
                    continue;
                }
                // 🔴 ZIP 规范要求用 '/',但现实里存在写成 '\' 的归档
                // (PowerShell Compress-Archive 就是一例)。只认 '/' 的话这类归档一条都扫不出来,
                // 而「没扫到」看起来和「你很安全」一模一样(第 6 注踩过)。
                String name = e.getName().replace('\\', '/');
                String lower = name.toLowerCase();

                if (isPomProps(lower)) {
                    String c = readCoord(zis.readAllBytes());
                    if (c != null) {
                        coords.add(c);
                    }
                } else if ("meta-inf/services/java.nio.file.spi.filesystemprovider".equals(lower)) {
                    for (String line : new String(zis.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8)
                            .split("\\R")) {
                        int hash = line.indexOf('#');
                        String cls = (hash >= 0 ? line.substring(0, hash) : line).trim();
                        if (!cls.isEmpty()) {
                            fsProviders.add(cls + "  (" + path + ")");
                        }
                    }
                } else if ("meta-inf/manifest.mf".equals(lower)) {
                    String[] mf = readManifest(zis);
                    mfSymbolic = mf[0];
                    mfVersion = mf[1];
                } else if (lower.endsWith(".jar") && depth < MAX_DEPTH) {
                    innerPaths.add(name);
                    innerBytes.add(zis.readAllBytes());
                }
            }
        } catch (IOException | IllegalArgumentException ex) {
            warnings.add("归档解析失败 " + path + ":" + ex.getMessage()
                    + "(🔴 这不等于「里面没有 jackson」,请手工确认)");
            return;
        }

        // 🔴 第二层防线:魔数对、也没抛异常,但一个条目都没解出来。
        //    ☠️ 2026-09-08 实测:魔数校验只挡住一半 —— 一个 PK 03 04 开头但**内容截断**的文件
        //    魔数是对的、ZipInputStream 也不抛异常,只是零条目。少了这一层它照样静默通过。
        if (entries == 0 && !isEmptyZip(bytes)) {
            unreadable++;
            warnings.add("这个文件魔数像 zip,但一个条目都解不出来(多半是截断或下载不全):" + path
                    + " —— 🔴 **这不等于「里面没有 jackson」**");
            return;
        }

        record0(path, coords, mfSymbolic, mfVersion);

        for (int i = 0; i < innerBytes.size(); i++) {
            scanArchive(path + "!/" + innerPaths.get(i), innerBytes.get(i), depth + 1);
        }
    }

    /**
     * 把一个归档里读到的坐标落成 {@link Artifact}。
     *
     * <p>坐标来源优先级:pom.properties(groupId 和版本都是直接读到的,最可靠)
     * &gt; MANIFEST 的 {@code Bundle-SymbolicName}(实测两个 groupId 的 jar 都带,形如
     * {@code com.fasterxml.jackson.core.jackson-databind})&gt; 文件名 + 大版本推断。
     * 前两者在 jar 被改名时依然正确,文件名会骗人。
     */
    private void record0(String path, List<String> coords, String mfSymbolic, String mfVersion) {
        String fileName = path.substring(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1);

        if (!coords.isEmpty()) {
            for (String c : coords) {
                // 形如 group:artifact:version
                String[] parts = c.split(":", 3);
                if (parts.length != 3) {
                    continue;
                }
                String group = parts[0];
                String art = parts[1];
                JacksonVersion v = JacksonVersion.parse(parts[2]);
                if (v == null) {
                    warnings.add("在 " + path + " 里读到 " + group + ":" + art
                            + " 但版本号无法解析:" + parts[2]
                            + "(🔴 这不等于「没有漏洞」,请手工确认版本)");
                    continue;
                }
                add(new Artifact(path, group, art, v, "pom.properties", false));
            }
            return;
        }

        // 没有 pom.properties(被重打包过或极老的构建)—— 退回 MANIFEST
        if (mfSymbolic != null) {
            for (String g : new String[]{CveTable.GROUP_2X, CveTable.GROUP_3X}) {
                for (String art : ARTIFACTS) {
                    if (!mfSymbolic.equals(g + "." + art)) {
                        continue;
                    }
                    JacksonVersion v = JacksonVersion.parse(mfVersion);
                    if (v == null) {
                        String[] fn = artifactAndVersionFromName(fileName);
                        v = fn == null ? null : JacksonVersion.parse(fn[1]);
                    }
                    if (v == null) {
                        warnings.add("识别出 " + g + ":" + art + " 但取不到版本号:"
                                + path + "(🔴 这不等于「没有漏洞」,请手工确认版本)");
                        return;
                    }
                    add(new Artifact(path, g, art, v, "MANIFEST", false));
                    return;
                }
            }
        }

        // 最后退回文件名。🔴 文件名里**没有 groupId** —— 两个 groupId 的 jar 叫一模一样的名字。
        //    只能按大版本推断:Central 上 com.fasterxml 只发过 2.x、tools.jackson 只发过 3.x
        //    (gen_rules.py 的 ASSERT8 每次重跑都会去 maven-metadata.xml 重新核实这个前提)。
        //    这是推断不是读到的,所以打 guessedGroup 标记,报告里要说出来。
        //    ⚠️ artifactId 反过来:它**就写在文件名里**,不用猜。
        String[] fn = artifactAndVersionFromName(fileName);
        if (fn == null) {
            return;                       // 不是 jackson 构件,正常跳过
        }
        JacksonVersion v = JacksonVersion.parse(fn[1]);
        if (v == null) {
            return;
        }
        String group = v.major() >= 3 ? CveTable.GROUP_3X : CveTable.GROUP_2X;
        add(new Artifact(path, group, fn[0].toLowerCase(), v, "文件名", true));
    }

    /** 从文件名取 {@code [artifactId, 版本]};不是 jackson 构件返回 null。 */
    private static String[] artifactAndVersionFromName(String fileName) {
        Matcher m = NAME_VER.matcher(fileName);
        return m.matches() ? new String[]{m.group(1), m.group(2)} : null;
    }

    /** 同一路径 + 同一坐标只记一条(重复上报会让人以为有两个问题 —— 第 5 注教训)。 */
    private void add(Artifact a) {
        for (Artifact x : found) {
            // 🔴 键必须是**完整坐标**:同一个 fat jar 里 databind 和 core 都在,
            //    只比 groupId 会把其中一个安静地吃掉 —— 而那正是本版要修的盲区。
            if (x.path().equals(a.path()) && x.coord().equals(a.coord())) {
                return;
            }
        }
        found.add(a);
    }

    /**
     * 从 pom.properties 读坐标,返回 {@code groupId:version}。
     *
     * <p>🔴 必须按 key 解析,<b>不能按行序</b>:实测同一批 jar 里键的顺序就不一样
     * (2.18.5 是 artifactId 在前,别的版本可能是 version 在前,有些前面还有一行注释)。
     */
    private static String readCoord(byte[] data) {
        Properties p = new Properties();
        try {
            p.load(new ByteArrayInputStream(data));
        } catch (IOException e) {
            return null;
        }
        String g = p.getProperty("groupId");
        String a = p.getProperty("artifactId");
        String v = p.getProperty("version");
        if (a == null || v == null) {
            return null;
        }
        boolean known = false;
        for (String x : ARTIFACTS) {
            known |= x.equals(a);
        }
        if (!known) {
            return null;                  // 只认我们有判定表的 artifact
        }
        if (!CveTable.GROUP_2X.equals(g) && !CveTable.GROUP_3X.equals(g)) {
            return null;                  // 只认这两个 groupId,防第三方同名构件
        }
        return g + ":" + a + ":" + v;
    }

    /**
     * 只读 MANIFEST 主属性段,返回 {@code [Bundle-SymbolicName, 版本]}。
     *
     * <p>⚠️ 第 4 注(bc-check)踩过:签名 jar 的 MANIFEST 可以上兆(每个类一个条目),
     * 整段读进来会撑破缓冲。{@link Manifest} 读主属性即可,不要遍历 entries。
     */
    private static String[] readManifest(ZipInputStream zis) {
        try {
            Manifest mf = new Manifest(new NonClosing(zis));
            String sym = mf.getMainAttributes().getValue("Bundle-SymbolicName");
            String ver = mf.getMainAttributes().getValue("Implementation-Version");
            if (ver == null) {
                ver = mf.getMainAttributes().getValue("Bundle-Version");
            }
            // Bundle-SymbolicName 可能带 ";singleton:=true" 之类的指令后缀
            if (sym != null) {
                int semi = sym.indexOf(';');
                sym = (semi >= 0 ? sym.substring(0, semi) : sym).trim();
            }
            return new String[]{sym, ver};
        } catch (IOException | IllegalArgumentException e) {
            return new String[]{null, null};
        }
    }

    /** Manifest 构造器会关掉流,而我们还要继续遍历同一个 ZipInputStream。 */
    private static final class NonClosing extends java.io.FilterInputStream {
        NonClosing(InputStream in) {
            super(in);
        }

        @Override
        public void close() {
            // 故意不关
        }
    }
}
