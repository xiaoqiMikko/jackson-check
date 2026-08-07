package dev.mikko.jacksoncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JacksonVersionTest {

    private static JacksonVersion v(String s) {
        JacksonVersion x = JacksonVersion.parse(s);
        assertNotNull(x, "应该能解析:" + s);
        return x;
    }

    @Test
    @DisplayName("四段版本号必须原样解析,不能被截成三段")
    void fourSegments() {
        // 🔴 jackson 的补丁线真的有第四段:2.9.10.8 / 2.12.7.1。
        //    截成 2.9.10 会让它在若干条 advisory 的分界线上判到错误的一侧。
        assertEquals(2, v("2.9.10.8").major());
        assertTrue(v("2.9.10.8").compareTo(v("2.9.10")) > 0, "2.9.10.8 必须大于 2.9.10");
        assertTrue(v("2.12.7.1").compareTo(v("2.12.7")) > 0);
        assertTrue(v("2.12.7.1").compareTo(v("2.12.8")) < 0);
    }

    @Test
    @DisplayName("缺省段补 0:2.18 == 2.18.0")
    void missingSegmentsAreZero() {
        assertEquals(v("2.18"), v("2.18.0"));
        assertEquals(v("3.1"), v("3.1.0.0"));
    }

    @Test
    @DisplayName("预发布排在同号正式版之前")
    void prereleaseOrdering() {
        assertTrue(v("3.0.0-rc1").compareTo(v("3.0.0")) < 0);
        assertTrue(v("2.18.0-rc1").compareTo(v("2.18.0-rc2")) < 0);
        assertTrue(v("3.0.0-alpha1").compareTo(v("3.0.0-rc1")) < 0);
    }

    @Test
    @DisplayName("解析不了必须返回 null,不许蒙一个值出来")
    void unparseableReturnsNull() {
        // 🔴 第 6 注 tomcat-check 踩过:限定符正则放宽成 [A-Za-z]+ 之后,
        //    "2.18.x" 这种通配写法会被「成功」解析成某个预发布版,
        //    于是区间判定拿它去比较 —— 既不报错也不正确。
        assertNull(JacksonVersion.parse("2.18.x"));
        assertNull(JacksonVersion.parse("2.18.LATEST"));
        assertNull(JacksonVersion.parse("${jackson.version}"));
        assertNull(JacksonVersion.parse(""));
        assertNull(JacksonVersion.parse(null));
        assertNull(JacksonVersion.parse("latest"));
    }

    @Test
    @DisplayName("维护分支 branch():求交集要按它分组")
    void branchGrouping() {
        assertEquals("2.18", v("2.18.9").branch());
        assertEquals("2.21", v("2.21.5").branch());
        assertEquals("3.1", v("3.1.5").branch());
        assertEquals("2.9", v("2.9.10.8").branch());
    }

    @Test
    @DisplayName("区间端点开闭照抄,不做换算")
    void rangeEndpoints() {
        // advisory 里 "< 2.18.8" 和 "<= 2.18.7" 两种写法都出现过,含义相同但端点不同。
        assertTrue(v("2.18.7").inRange("2.10.0", true, "2.18.8", false));
        assertFalse(v("2.18.8").inRange("2.10.0", true, "2.18.8", false));
        assertTrue(v("2.18.7").inRange("2.10.0", true, "2.18.7", true));
        assertFalse(v("2.10.0").inRange("2.10.0", false, "2.18.8", false), "开下限不含端点");
        assertTrue(v("2.10.0").inRange("2.10.0", true, "2.18.8", false), "闭下限含端点");
    }

    @Test
    @DisplayName("空上下限表示不设限")
    void openEnded() {
        assertTrue(v("2.0.0").inRange("", false, "3.0.0", false));
        assertTrue(v("9.9.9").inRange("2.0.0", true, "", false));
    }

    @Test
    @DisplayName("区间端点解析不了时返回 false —— 宁可不判,不许瞎判")
    void unparseableBoundIsNotInRange() {
        assertFalse(v("2.18.5").inRange("2.18.x", true, "2.19.0", false));
    }
}
