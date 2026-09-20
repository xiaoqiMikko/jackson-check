package dev.mikko.jacksoncheck;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** v0.2.0 新增的 4 类触发条件:重点测「不该命中的别命中」—— 文本匹配最常见的错是前缀吞并。 */
class NewMarkersTest {

    private static boolean matches(String marker, String code) {
        return Triggers.patterns().get(marker).matcher(code).find();
    }

    @Test
    @DisplayName("🔴 java.time.Duration 不是 CVE-2026-68497 —— 认裸 Duration 会让几乎所有项目命中")
    void xmlDatatypeIgnoresJavaTimeDuration() {
        assertFalse(matches("XMLDatatype", "import java.time.Duration; Duration ttl;"));
        assertTrue(matches("XMLDatatype", "import javax.xml.datatype.Duration;"));
        assertTrue(matches("XMLDatatype", "public XMLGregorianCalendar created;"));
        assertTrue(matches("XMLDatatype", "import javax.xml.datatype.*;"));
    }

    @Test
    @DisplayName("🔴 InetSocketAddress 不是 InetAddress(那条是已修的 54514)")
    void inetAddressIgnoresInetSocketAddress() {
        assertFalse(matches("InetAddress", "InetSocketAddress addr;"));
        assertTrue(matches("InetAddress", "public InetAddress bindHost;"));
    }

    @Test
    @DisplayName("Comparable 字段声明命中,实现 Comparable 接口不命中")
    void comparableProperty() {
        assertTrue(matches("ComparableProp", "public Comparable<?> value;"));
        assertTrue(matches("ComparableProp", "Comparable value = null;"));
        assertFalse(matches("ComparableProp", "class A implements Comparable<A> {"));
    }

    @Test
    @DisplayName("FS_PROVIDER 永不在源码里命中 —— 它只由构件扫描决定")
    void fsProviderNeverMatchesSource() {
        assertFalse(matches("FS_PROVIDER", "FileSystemProvider FS_PROVIDER provider"));
    }

    private static Path jarWith(Path dir, String name, String entry, String content) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (ZipOutputStream zo = new ZipOutputStream(bo)) {
            zo.putNextEntry(new ZipEntry(entry));
            zo.write(content.getBytes(StandardCharsets.UTF_8));
            zo.closeEntry();
        }
        Path p = dir.resolve(name);
        Files.write(p, bo.toByteArray());
        return p;
    }

    @Test
    @DisplayName("构件里注册的第三方 FileSystemProvider 被扫出来(含注释行与空行)")
    void scansFileSystemProviderService(@TempDir Path dir) throws IOException {
        jarWith(dir, "jimfs-1.3.0.jar", "META-INF/services/java.nio.file.spi.FileSystemProvider",
                "# comment\n\ncom.google.common.jimfs.SystemJimfsFileSystemProvider\n");
        Scanner s = new Scanner();
        s.scan(dir);
        assertEquals(1, s.fileSystemProviders().size());
        assertTrue(s.fileSystemProviders().get(0).startsWith("com.google.common.jimfs.SystemJimfsFileSystemProvider"));
    }

    @Test
    @DisplayName("19032:源码有 java.nio.file.Path,但依赖里没有第三方 provider → 只算部分成立")
    void pathWithoutProviderIsPartial(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("Cfg.java"),
                "import java.nio.file.Path; class Cfg { com.fasterxml.jackson.databind.ObjectMapper m; public Path workdir; }");
        SourceScan src = new SourceScan();
        src.scan(dir);
        Cve c = CveTable.all().stream().filter(x -> x.ghsaId().equals("GHSA-wjgm-6hv5-3cvf"))
                .filter(x -> x.groupId().equals(CveTable.GROUP_2X))
                .filter(x -> JacksonVersion.parse("2.21.5").inRange(x.low(), x.lowIncl(), x.high(), x.highIncl()))
                .findFirst().orElseThrow();
        List<Scanner.Artifact> art = List.of(new Scanner.Artifact("t.jar", CveTable.GROUP_2X, CveTable.ARTIFACT_DATABIND,
                JacksonVersion.parse("2.21.5"), "pom.properties", false));
        assertEquals(Applicability.Kind.HIT_PARTIAL, Applicability.judge(c, art, src, List.of()).kind());
        assertEquals(Applicability.Kind.HIT,
                Applicability.judge(c, art, src, List.of("x.Provider  (a.jar)")).kind());
    }
}
