# jackson-check

**jackson-databind 2026 年 11 条安全公告自查工具。零依赖单 jar,不联网。**

它回答两个 Dependabot 回答不了的问题:

1. **这 11 条里,我真正中几条?** —— 扫你的源码找触发条件(`@JsonView` / 多态类型 / 大小写不敏感匹配……),把「装了受影响版本」降噪成「真的踩到那个特性」。
2. **我到底该升到哪个版本?** —— 11 条 advisory 给出的修复版**互相不一致**,逐条求交集才有答案。

```bash
java -jar jackson-check.jar ./target ./src
```

---

## 🔥 三个实测结论(每条都能自己复现)

### 一、升到 advisory 里出现最多的那个版本,仍然中三条

2026 年这 11 条里,**8 条**都写着修复版是 `2.21.4` / `2.18.8` / `3.1.4`。照着升的人以为修完了。

实际逐条求交集的答案是:

| 维护分支 | advisory 上最常见 | **真正到位的版本** |
|---|---|---|
| 2.18.x | 2.18.8 | **2.18.9** |
| 2.21.x | 2.21.4 | **2.21.5** |
| 2.22.x | — | **2.22.1** |
| 3.1.x | 3.1.4 | **3.1.5** |
| 3.2.x | — | **3.2.1** |

顶高目标的是这三条:

- `CVE-2026-54515` —— 大小写不敏感反序列化绕过逐属性 `@JsonIgnoreProperties`
- `CVE-2026-59889` —— `@JsonView` 对 `@JsonUnwrapped` 容器属性失效
- 🔴 **`GHSA-mhm7-754m-9p8w` —— 没有 CVE 号**,advisory 原文自己写着:

  > the fix was never backported to 2.21 or 2.18 … **Users on 2.21.4 and 2.18.8 who upgraded per the published advisories remain vulnerable**

  它是一个**补丁缺口**:3.x 线修了,2.18 / 2.21 线的回移漏了。因为没有 CVE 号,按 CVE 编号是搜不到它的。

跑一次就能看到:

```bash
# 已经升到 2.21.4 的项目
java -jar jackson-check.jar ./lib ./src
#   Dependabot 会报给你:3 条
#   🔥 注意:如果你照着 advisory 里出现最多的那个修复版升,以下 3 条仍然中
```

### 二、Jackson 3 换了 groupId,而 advisory 把两个坐标的版本区间贴串了

| 坐标 | Maven Central 上实际发布过 |
|---|---|
| `com.fasterxml.jackson.core:jackson-databind` | **只有 2.x** |
| `tools.jackson.core:jackson-databind` | **只有 3.x** |

而 advisory 的结构化字段里:

- `com.fasterxml.jackson.core` 上挂着 **6 条 3.x 区间**,修复版 `3.1.4` → 那个坐标下 **HTTP 404**
- `tools.jackson.core` 上挂着 **1 条 2.x 区间**,修复版 `2.21.4` → 同样 **HTTP 404**

**照抄 advisory 的工具会让你去装一个不存在的东西。** 本工具在生成判定表时逐个 HEAD 请求实测可获取性,拿不到的会在报告里标出来,不会印成升级建议。

两个坐标的 `artifactId` 和 jar 文件名**一模一样**,只有 `META-INF` 里分得清 —— 所以本工具按坐标判定,不按文件名。

### 三、降噪:11 条里多数只在用了对应特性的代码里成立

| 触发条件 | 关联条目 |
|---|---|
| `@JsonView` | CVE-2026-54517 / 54518 / 59889 / GHSA-mhm7 |
| `@JsonTypeInfo` / `activateDefaultTyping` / `PolymorphicTypeValidator` | CVE-2026-54512 / 54513 |
| `@JsonIgnoreProperties` + `ACCEPT_CASE_INSENSITIVE_PROPERTIES` | CVE-2026-54515 |
| `@JsonIgnore` + `@JsonProperty` 改名 | CVE-2026-54516 |
| Java Record + `PropertyNamingStrategy` + `@JsonIgnore` | CVE-2026-59888 |
| `InetSocketAddress` 字段 | CVE-2026-54514 |
| `readTree()` + `JsonNode.toString()` | CVE-2026-50193 |

同一个 `2.18.5`,两份代码的结果完全不同:

```
一份用了多态类型 + @JsonView 的代码   → Dependabot 报 7 条,真中 6 条
一份只 new 了个 ObjectMapper 的代码   → Dependabot 报 7 条,真中 0 条
```

---

## 🔴 这个工具不能证明什么

两个方向都要说清楚,只说一边就是在误导:

**①「未找到触发条件」不等于安全。** 三种情况会让它变成假的安心:

1. 你依赖的**第三方库**在它自己的代码里用了这些注解 —— 我们扫不到它的源码;
2. 注解可能通过 mixin(`ObjectMapper.addMixIn`)等运行时方式加上,源码里根本没有那个词;
3. 你可能压根没把源码目录传进来。

**②「触发条件全部成立」也不等于确认中招。** 标记是按**整个代码库**聚合的,不是按同一个类或同一个字段。比如某条要求 `@JsonView` 和 `@JsonUnwrapped` 标在同一个属性上,而我们只能看到这两个词都在你的代码里出现过。

**本工具只做文本匹配,不做 AST 解析。** 这是有意的取舍:关键路径必须能被人读懂并自己核对 —— 一个看不懂的 AST 判定出错时没人能发现。

> **版本判定(第一步)是硬的;触发条件判定(第二步)只用来排优先级,不用来免除风险。**

**关于 Dependabot 盲区:本批 11 条一条都没有。** 官方仓库 advisory 页面 11 条,按两个坐标反查合计 11 条,差值为 0 —— 这是**查了两个源之后**得出的结论,不是只查一个源的默认值(`tools/gen_rules.py` 的 ASSERT2 每次重跑都会重新核实)。所以这一批 Dependabot 的**版本告警是准的**,本工具的价值在降噪和求交集,不在补漏。

---

## 用法

```bash
java -jar jackson-check.jar <路径...> [选项]

  <路径>        jar / war / 目录。目录会同时找构建产物(定版本)和 .java 源码(定触发条件)
  --src <路径>  额外指定源码目录
  --no-src      不扫源码(只按版本判,粒度等同 Dependabot)
  --all         把未命中的条目也列出来
  -v, --version 版本号
  -h, --help    帮助
```

**退出码**:`0` = 版本没中 · `2` = 版本中但源码里没找到触发条件(或没扫源码)· `3` = 触发条件也成立。可直接用在 CI 里。

能认的形态:普通 jar、Spring Boot fat jar(`BOOT-INF/lib/`)、传统 WAR(`WEB-INF/lib/`)、shade 进宿主 jar 的 jackson(依赖坐标看不见,`META-INF/maven` 还在)。

```bash
# Maven 项目
mvn package && java -jar jackson-check.jar target src

# 只有一个成品 jar
java -jar jackson-check.jar app.jar

# Gradle 项目
java -jar jackson-check.jar build/libs src/main/java
```

需要 **Java 17+**。运行时零依赖 —— 尤其**不依赖 jackson 本身**。

---

## 判定表是生成的,不是手抄的

`tools/gen_rules.py` 从两个一手源生成 `CveTable.java`:

- **源 A** `/repos/FasterXML/jackson-databind/security-advisories` —— 维护者发布的条目全集 + 描述原文
- **源 B** `/advisories?ecosystem=maven&affects=<坐标>` —— Dependabot 实际用的坐标索引(两个 groupId 各查一次)

11 条 advisory 展开成 **37 条「advisory × 坐标 × 版本区间」规则**,带 **13 条断言**,任一不满足就中止且不写文件 —— 防「解析失败生成空壳表而测试照样全绿」:

| 断言 | 查什么 |
|---|---|
| ASSERT2 | ⭐ 双源盲区对比,差值必须为 0 或被逐条解释 |
| ASSERT6 | 两个 groupId 都要覆盖 |
| ASSERT7 | 每个修复版逐个 HEAD 请求探 Maven Central 可获取性 |
| ASSERT8 | 双向幽灵:拉 `maven-metadata.xml` 证明整条大版本线在那个坐标下不存在 |
| ASSERT9 | 逐分支求交集,且必须真的高于同分支最低修复版 |
| ASSERT11 | 每条触发条件的锚点串必须**逐字**出现在官方描述原文里 |
| ASSERT12 | 每条都要有 CVSS 分数(两个源取并集) |

```bash
python tools/gen_rules.py      # 需要已登录的 gh CLI
```

**56 个单元测试 + 7 个真实构件端到端场景**(真 jar:2.13.0 / 2.18.5 / 2.21.2 / 2.21.4 / 2.21.5 / 3.1.2 / 3.1.5)。

---

## 覆盖的条目

| 编号 | 级别 | 主题 |
|---|---|---|
| CVE-2026-54512 | **high** 8.1 | `PolymorphicTypeValidator` 泛型参数绕过 |
| CVE-2026-54513 | **high** 8.1 | `allowIfSubTypeIsArray()` 数组子类型 allowlist 绕过 |
| CVE-2026-50193 | medium 7.5 | 深层嵌套 `JsonNode.toString()` 栈溢出 |
| CVE-2026-54514 | medium 5.3 | `InetSocketAddress` 反序列化触发 DNS(SSRF) |
| CVE-2026-54515 | medium 5.3 | 大小写不敏感重建覆盖 `@JsonIgnoreProperties` |
| CVE-2026-54516 | medium 5.3 | 改名的 `@JsonIgnore` setter 仍可经私有字段写入 |
| CVE-2026-54517 | medium 5.3 | `@JsonView` 对 setterless creator 属性失效 |
| CVE-2026-54518 | medium 6.5 | `@JsonView` 对 unwrapped creator 参数失效 |
| CVE-2026-59888 | medium 6.5 | Record 属性上的 `@JsonIgnore` 被命名策略绕过 |
| CVE-2026-59889 | medium 6.5 | `@JsonView` 对 `@JsonUnwrapped` 容器属性失效 |
| **GHSA-mhm7-754m-9p8w** | medium 6.5 | **无 CVE 号** · `@JsonView` + `As.EXTERNAL_PROPERTY` 补丁缺口 |

---

## License

Apache-2.0

<!-- cta:hire -->

---

## 需要更进一步的排查?

这个工具回答的是「**我中没中**」。下面这些它答不了,可以找我做:

- 依赖被 shade / relocate 过,或者构建产物根本拿不到
- 要判的是「这条 CVE 在**我们的调用链上**到底会不会触发」,而不只是版本命中
- 要按你们自己的构建流程或内网环境做定制、接进现有流水线
- 手上是**另一个**组件的同类问题,还没有现成工具

📮 **sikongjuechen@gmail.com** —— 说清情况,我 24 小时内给你一页书面答复:
能不能做、难在哪、大概多久。**这一步免费,也不用你先承诺什么。**
