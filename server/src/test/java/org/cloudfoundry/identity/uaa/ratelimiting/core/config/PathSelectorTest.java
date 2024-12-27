package org.cloudfoundry.identity.uaa.ratelimiting.core.config;

import java.util.List;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PathSelectorTest {
    private static final String NAME = "login";

    @Test
    void pathMatchType() {
        assertNull(PathSelector.pathMatchType(""), "empty");
        assertNull(PathSelector.pathMatchType("FRED"), "FRED");
        for (PathMatchType value : PathMatchType.values()) {
            assertEquals(value, PathSelector.pathMatchType(value.toString()), "unchanged Case " + value);
            assertEquals(value, PathSelector.pathMatchType(value.toString().toLowerCase()), "lower Case " + value);
            assertEquals(value, PathSelector.pathMatchType(value.toString().toUpperCase()), "upper Case " + value);
        }
    }

    @Test
    void parse() {
        checkNull(null);
        checkNull("");
        checkNull("   ");

        checkException(1, "fred");
        checkException(2, "fred:");
        checkException(3, "fred:/login");
        checkException(11, "equals");
        checkException(12, "equals:");
        checkException(13, "equals:login");
        checkException(21, "StartsWith");
        checkException(22, "StartsWith:");
        checkException(23, "StartsWith:login");
        checkException(21, "Contains");
        checkException(22, "Contains:");
        checkException(23, "Contains:  "); // w/ extraneous spaces ignored
        checkException(31, "Other:login");
        checkException(41, "All:login");

        checkOK("equals  :  /login", PathMatchType.Equals, "/login"); // w/ extraneous spaces ignored
        checkOK("StartsWith:/login", PathMatchType.StartsWith, "/login");
        checkOK("Contains:/login", PathMatchType.Contains, "/login");
        checkOK("Other", PathMatchType.Other, "");
        checkOK("Other:", PathMatchType.Other, "");
        checkOK("All", PathMatchType.All, "");
        checkOK("All:", PathMatchType.All, "");
    }

    private PathSelector check(int offsetIndex, String selectorStr) {
        return PathSelector.parse(selectorStr, offsetIndex, NAME);
    }

    private void checkException(int offsetIndex, String selectorStr) {
        PathSelector ps;
        try {
            ps = check(offsetIndex, selectorStr);
        }
        catch (RateLimitingConfigException e) {
            String msg = e.getMessage();
            String startsWithFragment = NAME + "'s PathSelector[" + offsetIndex + "]";
            String containsFragment = " in '" + selectorStr.trim() + "'";
            if (!msg.startsWith(startsWithFragment) || !msg.contains(containsFragment)) {
                fail("Message \"" + msg + "\" did not:\n" +
                        "  startWith: \"" + startsWithFragment + "\"\n" +
                        "  & contain: \"" + containsFragment + "\"");
            }
            return;
        }
        assertNotNull(ps, "null from '" + selectorStr + "'");
        fail("from '" + selectorStr + "' did NOT expect: '" + ps + "'");
    }

    private void checkNull(String selectorStr) {
        PathSelector ps = check(0, selectorStr);
        assertNull(ps, "expected null from '" + selectorStr + "', but got: " + ps);
    }

    private void checkOK(String selectorStr, PathMatchType pathMatchType, String path) {
        PathSelector ps = check(0, selectorStr);
        assertNotNull(ps, "null from '" + selectorStr + "'");
        assertEquals(pathMatchType, ps.getType(), "type from '" + selectorStr + "'");
        assertEquals(path, ps.getPath(), "path from '" + selectorStr + "'");
    }

    @Test
    void listFrom() {
        checkException(null);
        checkException(List.of());
        checkException(List.of("", "  "));

        List<PathSelector> ps = PathSelector.listFrom(NAME, List.of(
                "equals:/login",
                "StartsWith:/login",
                "Contains:/login",
                "Other",
                "All"));
        assertEquals(5, ps.size());
        checkOK(ps, 0, PathMatchType.Equals, "/login");
        checkOK(ps, 1, PathMatchType.StartsWith, "/login");
        checkOK(ps, 2, PathMatchType.Contains, "/login");
        checkOK(ps, 3, PathMatchType.Other, "");
        checkOK(ps, 4, PathMatchType.All, "");
    }

    private void checkOK(List<PathSelector> selectors, int offsetIndex, PathMatchType type, String path) {
        PathSelector ps = selectors.get(offsetIndex);
        assertNotNull(ps, "null from offsetIndex: " + offsetIndex);
        assertEquals(type, ps.getType(), "type from offsetIndex: " + offsetIndex);
        assertEquals(path, ps.getPath(), "path from offsetIndex: " + offsetIndex);
    }

    private void checkException(List<String> pathSelectors) {
        List<PathSelector> ps;
        try {
            ps = PathSelector.listFrom(NAME, pathSelectors);
        }
        catch (RateLimitingConfigException e) {
            String msg = e.getMessage();
            String startsWithFragment = "No pathSelectors";
            if (!msg.startsWith(startsWithFragment)) {
                fail("Message \"" + msg + "\" did not:\n" +
                        "  startWith: \"" + startsWithFragment + "\"");
            }
            return;
        }
        assertNotNull(ps, "null from: " + pathSelectors);
        fail("from '" + pathSelectors + "' did NOT expect: '" + ps + "'");
    }
}