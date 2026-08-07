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

    private static final String MVN_2X = "meta-inf/maven/" + CveTable.GROUP_2X + "/"
            + CveTable.ARTIFACT + "/pom.properties";
    private static final String MVN_3X = "meta-inf/maven/" + CveTable.GROUP_3X + "/"
            + CveTable.ARTIFACT + "/pom.properties";

    private static final Pattern NAME_VER =
            Pattern.compile("^" + CveTable.ARTIFACT + "-(\\d[\\w.\\-]*)\\.jar$",
                    Pattern.CASE_INSENSITIVE);

    /**
     * 扫到的一份 jackson-databind。
     *
     * @param path    它在哪(fat jar 内的用 {@code !/} 分隔)
     * @param groupId 坐标的 groupId —— 2.x 与 3.x 不同,判定时必须区分
     * @param version 版本
     * @param source  坐标与版本取自哪里:pom.properties / MANIFEST / 文件名
     * @param guessedGroup groupId 是不是**按大版本推断**出来的(而非从元数据直接读到)
     */
    public record Artifact(String path, String groupId, JacksonVersion version,
                           String source, boolean guessedGroup) {
    }

    private final List<Artifact> found = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

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

    private void scanArchive(String path, byte[] bytes, int depth) {
        List<byte[]> innerBytes = new ArrayList<>();
        List<String> innerPaths = new ArrayList<>();
        List<String> coords = new ArrayList<>();
        String mfSymbolic = null;
        String mfVersion = null;

        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.isDirectory()) {
                    continue;
                }
                // 🔴 ZIP 规范要求用 '/',但现实里存在写成 '\' 的归档
                // (PowerShell Compress-Archive 就是一例)。只认 '/' 的话这类归档一条都扫不出来,
                // 而「没扫到」看起来和「你很安全」一模一样(第 6 注踩过)。
                String name = e.getName().replace('\\', '/');
                String lower = name.toLowerCase();

                if (lower.endsWith(MVN_2X) || lower.endsWith(MVN_3X)) {
                    String c = readCoord(zis.readAllBytes());
                    if (c != null) {
                        coords.add(c);
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
                int i = c.lastIndexOf(':');
                String group = c.substring(0, i);
                JacksonVersion v = JacksonVersion.parse(c.substring(i + 1));
                if (v == null) {
                    warnings.add("在 " + path + " 里读到 " + group + ":" + CveTable.ARTIFACT
                            + " 但版本号无法解析:" + c.substring(i + 1)
                            + "(🔴 这不等于「没有漏洞」,请手工确认版本)");
                    continue;
                }
                add(new Artifact(path, group, v, "pom.properties", false));
            }
            return;
        }

        // 没有 pom.properties(被重打包过或极老的构建)—— 退回 MANIFEST
        if (mfSymbolic != null) {
            for (String g : new String[]{CveTable.GROUP_2X, CveTable.GROUP_3X}) {
                if (mfSymbolic.equals(g + "." + CveTable.ARTIFACT)) {
                    JacksonVersion v = JacksonVersion.parse(mfVersion);
                    if (v == null) {
                        v = versionFromName(fileName);
                    }
                    if (v == null) {
                        warnings.add("识别出 " + g + ":" + CveTable.ARTIFACT + " 但取不到版本号:"
                                + path + "(🔴 这不等于「没有漏洞」,请手工确认版本)");
                        return;
                    }
                    add(new Artifact(path, g, v, "MANIFEST", false));
                    return;
                }
            }
        }

        // 最后退回文件名。🔴 文件名里**没有 groupId** —— 两个坐标的 jar 叫一模一样的名字。
        //    只能按大版本推断:Central 上 com.fasterxml 只发过 2.x、tools.jackson 只发过 3.x
        //    (gen_rules.py 的 ASSERT8 每次重跑都会去 maven-metadata.xml 重新核实这个前提)。
        //    这是推断不是读到的,所以打 guessedGroup 标记,报告里要说出来。
        JacksonVersion v = versionFromName(fileName);
        if (v == null) {
            return;                       // 不是 jackson-databind 构件,正常跳过
        }
        String group = v.major() >= 3 ? CveTable.GROUP_3X : CveTable.GROUP_2X;
        add(new Artifact(path, group, v, "文件名", true));
    }

    private static JacksonVersion versionFromName(String fileName) {
        Matcher m = NAME_VER.matcher(fileName);
        return m.matches() ? JacksonVersion.parse(m.group(1)) : null;
    }

    /** 同一路径 + 同一坐标只记一条(重复上报会让人以为有两个问题 —— 第 5 注教训)。 */
    private void add(Artifact a) {
        for (Artifact x : found) {
            if (x.path().equals(a.path()) && x.groupId().equals(a.groupId())) {
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
        if (!CveTable.ARTIFACT.equals(a) || v == null) {
            return null;
        }
        if (!CveTable.GROUP_2X.equals(g) && !CveTable.GROUP_3X.equals(g)) {
            return null;                  // 只认这两个 groupId,防第三方同名构件
        }
        return g + ":" + v;
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
