package dev.mikko.jacksoncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 源码扫描是本注唯一的新东西,也是唯一可能把「你真中 3 条」这个数字算错的地方,
 * 所以误报和漏报两个方向都要单独钉住。
 */
class SourceScanTest {

    private static SourceScan scan(Path dir, String name, String content) throws IOException {
        Path f = dir.resolve(name);
        Files.createDirectories(f.getParent() == null ? dir : f.getParent());
        Files.write(f, content.getBytes(StandardCharsets.UTF_8));
        SourceScan s = new SourceScan();
        s.scan(dir);
        return s;
    }

    @Test
    @DisplayName("🔴 @JsonIgnoreProperties 不能被 @JsonIgnore 的匹配吞掉")
    void jsonIgnoreDoesNotSwallowJsonIgnoreProperties(@TempDir Path dir) throws IOException {
        // 这是文本匹配最典型的误报:前缀吞并。
        // 吞掉的后果是任何用了 @JsonIgnoreProperties 的项目都会被判成中了
        // IGNORED_SETTER_RENAME(CVE-2026-54516),而那条其实要求 setter 上有 @JsonIgnore。
        SourceScan s = scan(dir, "A.java", """
                @JsonIgnoreProperties({"a","b"})
                public class A { }
                """);
        assertTrue(s.hasMarker("@JsonIgnoreProperties"));
        assertFalse(s.hasMarker("@JsonIgnore"), "@JsonIgnoreProperties 不该算作 @JsonIgnore");
    }

    @Test
    @DisplayName("真的 @JsonIgnore 要认出来")
    void realJsonIgnoreIsFound(@TempDir Path dir) throws IOException {
        SourceScan s = scan(dir, "B.java", """
                public class B {
                    @JsonIgnore
                    public void setRole(String r) { }
                }
                """);
        assertTrue(s.hasMarker("@JsonIgnore"));
    }

    @Test
    @DisplayName("🔴 注释里的示例不算命中 —— 否则「你真中几条」这个数字就没意义了")
    void commentsAreStripped(@TempDir Path dir) throws IOException {
        SourceScan s = scan(dir, "C.java", """
                public class C {
                    // 例如 @JsonView(Public.class) 可以做写入侧门控
                    /* 也可以用 @JsonUnwrapped
                       跨多行的块注释 @JsonTypeInfo */
                    /** Javadoc 里的 @JsonView 同样不算 */
                    int x;
                }
                """);
        assertFalse(s.hasMarker("@JsonView"), "行注释与 Javadoc 里的不算");
        assertFalse(s.hasMarker("@JsonUnwrapped"), "块注释里的不算");
        assertFalse(s.hasMarker("@JsonTypeInfo"), "跨行块注释里的不算");
    }

    @Test
    @DisplayName("🔴 字符串里的 // 不能把整行当注释抹掉(这是漏报方向的错)")
    void urlInStringDoesNotStartComment(@TempDir Path dir) throws IOException {
        SourceScan s = scan(dir, "D.java", """
                public class D {
                    String url = "https://example.com/api"; @JsonView(Admin.class) String secret;
                }
                """);
        assertTrue(s.hasMarker("@JsonView"), "URL 里的 // 不该把后面的注解吃掉");
    }

    @Test
    @DisplayName("文本块整块跳过,且不让状态机错位")
    void textBlockDoesNotDesync(@TempDir Path dir) throws IOException {
        SourceScan s = scan(dir, "E.java", """
                public class E {
                    String json = \"""
                        { "note": "这里写了 @JsonView 但它是数据不是代码" }
                        \""";
                    @JsonUnwrapped Address addr;
                }
                """);
        assertFalse(s.hasMarker("@JsonView"), "文本块里的不算");
        assertTrue(s.hasMarker("@JsonUnwrapped"), "文本块之后的代码必须照常扫到");
    }

    @Test
    @DisplayName("剥注释后行号不变 —— 证据要指得准")
    void lineNumbersPreserved(@TempDir Path dir) throws IOException {
        SourceScan s = scan(dir, "F.java", """
                /* 第 1 行
                   第 2 行 */
                public class F {
                    @JsonView(Admin.class) String s;
                }
                """);
        SourceScan.Evidence ev = s.hits().get("@JsonView").get(0);
        assertEquals(4, ev.line(), "@JsonView 在第 4 行");
    }

    @Test
    @DisplayName("record 标记只认 Record 声明,不认叫 record 的变量")
    void recordMarkerIsNarrow(@TempDir Path dir) throws IOException {
        SourceScan s = scan(dir, "G.java", """
                public class G {
                    void f() { String record = "x"; log(record); }
                }
                """);
        assertFalse(s.hasMarker("record"), "普通变量名 record 不算 Record 声明");

        SourceScan s2 = scan(dir, "H.java", """
                public record User(String name, @JsonIgnore String role) { }
                """);
        assertTrue(s2.hasMarker("record"), "真的 Record 声明要认出来");
    }

    @Test
    @DisplayName("ObjectMapper 上锚:区分「没用 jackson」和「用了但没用这些特性」")
    void anchorSeparatesTwoCases(@TempDir Path dir) throws IOException {
        SourceScan none = scan(dir, "I.java", "public class I { int x; }\n");
        assertFalse(none.usesJackson());

        SourceScan uses = scan(dir, "J.java", """
                public class J {
                    ObjectMapper m = new ObjectMapper();
                }
                """);
        assertTrue(uses.usesJackson());
        assertFalse(uses.hasMarker("@JsonView"), "用了 jackson 但没用 @JsonView —— 这才是降噪");
    }

    @Test
    @DisplayName("跳过构建产物目录,不重复计数")
    void skipsBuildDirs(@TempDir Path dir) throws IOException {
        Path t = dir.resolve("target/generated");
        Files.createDirectories(t);
        Files.write(t.resolve("Gen.java"), "@JsonView class Gen {}".getBytes(StandardCharsets.UTF_8));
        SourceScan s = new SourceScan();
        s.scan(dir);
        assertFalse(s.hasMarker("@JsonView"), "target/ 下的不该扫");
        assertEquals(0, s.filesScanned());
    }

    @Test
    @DisplayName("stripComments 保持行数不变")
    void stripKeepsLineCount() {
        String src = "a\n/* x\ny */\nb\n// c\nd\n";
        assertEquals(src.split("\n", -1).length,
                SourceScan.stripComments(src).split("\n", -1).length);
    }
}
