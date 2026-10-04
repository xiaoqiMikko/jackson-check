package dev.mikko.jacksoncheck;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * 源码触发条件标记表,由 tools/gen_rules.py 生成,请勿手工编辑。
 *
 * <p>🔴 <b>只做文本匹配,不做 AST</b> —— 这是有意的设计取舍:
 * 关键路径必须能被人读懂并自己核对,一个看不懂的 AST 判定出错时没人能发现。
 * 代价是<b>匹配不到 ≠ 安全</b>(传递依赖里的库也可能用这些注解,而我们扫不到它的源码),
 * 报告里必须原样说出这一点。
 */
public final class Triggers {
    private Triggers() {}

    /** 判断「这份源码到底用没用 jackson」的上锚。 */
    public static final String ANCHOR = "ObjectMapper";

    private static final Map<String, Pattern> PATTERNS = new LinkedHashMap<>();
    private static final Map<String, String> LABELS = new LinkedHashMap<>();

    static {
        put("@JsonView", "@JsonView\\b", "@JsonView 注解");
        put("@JsonUnwrapped", "@JsonUnwrapped\\b", "@JsonUnwrapped 注解");
        put("@JsonTypeInfo", "@JsonTypeInfo\\b", "@JsonTypeInfo 注解(多态类型)");
        put("@JsonIgnore", "@JsonIgnore(?![A-Za-z])", "@JsonIgnore 注解(不含 @JsonIgnoreProperties)");
        put("@JsonIgnoreProperties", "@JsonIgnoreProperties\\b", "@JsonIgnoreProperties 注解");
        put("@JsonProperty", "@JsonProperty\\b", "@JsonProperty 注解");
        put("PolymorphicTypeValidator", "\\bPolymorphicTypeValidator\\b|\\bactivateDefaultTyping\\b", "PolymorphicTypeValidator / activateDefaultTyping");
        put("allowIfSubTypeIsArray", "\\ballowIfSubTypeIsArray\\b", "allowIfSubTypeIsArray()");
        put("ACCEPT_CASE_INSENSITIVE_PROPERTIES", "\\bACCEPT_CASE_INSENSITIVE_PROPERTIES\\b", "ACCEPT_CASE_INSENSITIVE_PROPERTIES");
        put("InetSocketAddress", "\\bInetSocketAddress\\b", "InetSocketAddress 类型");
        put("PropertyNamingStrategy", "\\bPropertyNamingStrategy\\b|@JsonNaming\\b", "PropertyNamingStrategy / @JsonNaming");
        put("EXTERNAL_PROPERTY", "\\bEXTERNAL_PROPERTY\\b", "As.EXTERNAL_PROPERTY");
        put("readTree", "\\breadTree\\s*\\(", "ObjectMapper.readTree()");
        put("JsonNode", "\\bJsonNode\\b", "JsonNode 类型");
        put("record", "\\brecord\\s+[A-Z]\\w*\\s*\\(", "Java Record 声明");
        put("XMLDatatype", "\\bXMLGregorianCalendar\\b|\\bjavax\\.xml\\.datatype\\.(?:Duration\\b|\\*)", "javax.xml.datatype.Duration / XMLGregorianCalendar");
        put("NioPath", "\\bjava\\.nio\\.file\\.(?:Path\\b|\\*)", "java.nio.file.Path 类型");
        put("FS_PROVIDER", "(?!)", "依赖里注册了第三方 FileSystemProvider(扫构件,不扫源码)");
        put("InetAddress", "\\bInetAddress\\b", "java.net.InetAddress 类型");
        put("defaultImpl", "\\bdefaultImpl\\s*=", "@JsonTypeInfo 的 defaultImpl 兜底");
        put("@JsonIdentityInfo", "@JsonIdentityInfo\\b", "@JsonIdentityInfo 注解");
        put("ComparableProp", "\\bComparable\\s*(?:<[^>]*>)?\\s+\\w+\\s*[;=]", "Comparable 类型的字段声明");
        put("StreamReadConstraints", "\\bStreamReadConstraints\\b|\\bsetStreamReadConstraints\\b", "显式配置过 StreamReadConstraints 限流");
        put("CharInputParse", "\\b(?:readValue|readTree|createParser)\\s*\\(\\s*new\\s+(?:StringReader|CharArrayReader|InputStreamReader|FileReader)\\b", "从 String / Reader / char[] 解析(显式写法)");
        put("AsyncParser", "\\bcreateNonBlockingByteArrayParser\\b|\\bfeedInput\\s*\\(|\\bNON_BLOCKING\\b", "非阻塞(async)解析器");
        put("DataInputParse", "\\bjava\\.io\\.DataInput\\b|\\bcreateParser\\s*\\(\\s*(?:new\\s+)?\\w*DataInput", "从 java.io.DataInput 解析");
        put("ByteOffsetParse", "\\b(?:readValue|createParser)\\s*\\(\\s*\\w+\\s*,\\s*\\d+\\s*,", "带 offset/length 的 byte[] 解析");
        put("ObjectMapper", "\\bObjectMapper\\b", "ObjectMapper(是否用到 jackson 的上锚)");
    }

    private static void put(String name, String regex, String label) {
        PATTERNS.put(name, Pattern.compile(regex));
        LABELS.put(name, label);
    }

    public static Map<String, Pattern> patterns() { return PATTERNS; }

    public static String label(String marker) { return LABELS.getOrDefault(marker, marker); }
}
