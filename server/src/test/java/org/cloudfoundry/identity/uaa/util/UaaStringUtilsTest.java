package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(PollutionPreventionExtension.class)
class UaaStringUtilsTest {

    private Map<String, Object> map;
    private Properties properties;

    @BeforeEach
    void setUp() {
        map = new HashMap<>();
        map.put("test.password", "password");
        map.put("test.signing-key", "signing-key");
        map.put("test.secret", "secret");
        map.put("password", "password");
        map.put("signing-key", "signing-key");
        map.put("secret", "secret");

        properties = new Properties();
        for (String key : map.keySet()) {
            properties.put(key, map.get(key));
        }

        Map<String, Object> submap = new HashMap<>(map);
        map.put("submap", submap);
    }

    @Test
    void nonNull() {
        assertNull(UaaStringUtils.nonNull());
        assertNull(UaaStringUtils.nonNull((String) null));
        assertNull(UaaStringUtils.nonNull(null, null));
        assertEquals("7", UaaStringUtils.nonNull("7"));
        assertEquals("6", UaaStringUtils.nonNull(null, "6"));
        assertEquals("5", UaaStringUtils.nonNull(null, null, "5"));
        assertEquals("1", UaaStringUtils.nonNull(null, null, "1", "2"));
        assertEquals("2", UaaStringUtils.nonNull(null, null, null, "2"));
    }

    @Test
    void replace_zone_variables() {
        replaceZoneVariables(IdentityZone.getUaa());
        IdentityZone zone = MultitenancyFixture.identityZone("otherId", "otherDomain");
        replaceZoneVariables(zone);
    }

    @Test
    void camelToUnderscore() {
        assertEquals("test_camel_case", UaaStringUtils.camelToUnderscore("testCamelCase"));
        assertEquals("testcamelcase", UaaStringUtils.camelToUnderscore("testcamelcase"));
        assertEquals("test_camel_case", UaaStringUtils.camelToUnderscore("test_camel_case"));
        assertEquals("test_camel_case", UaaStringUtils.camelToUnderscore("test_Camel_Case"));
    }

    @Test
    void getErrorName() {
        assertEquals("illegal_argument", UaaStringUtils.getErrorName(new IllegalArgumentException()));
        assertEquals("null_pointer", UaaStringUtils.getErrorName(new NullPointerException()));
    }

    @Test
    void hidePasswords() {
        Map<String, ?> result = UaaStringUtils.hidePasswords(map);
        checkPasswords(result);

        Properties presult = UaaStringUtils.hidePasswords(properties);
        checkPasswords(new HashMap(presult));
    }

    @Test
    void escapeRegExCharacters() {
        assertTrue(matches(UaaStringUtils.escapeRegExCharacters(".*"), ".*"));
        assertFalse(matches(UaaStringUtils.escapeRegExCharacters(".*"), ".some other string"));
        assertTrue(matches(UaaStringUtils.escapeRegExCharacters("x"), "x"));
        assertTrue(matches(UaaStringUtils.escapeRegExCharacters("x*x"), "x*x"));
        assertEquals(UaaStringUtils.escapeRegExCharacters("\\"), "\\\\");
        assertEquals(UaaStringUtils.escapeRegExCharacters("["), "\\[");
    }

    @Test
    void constructSimpleWildcardPattern() {
        assertEquals("space\\.[^\\\\.]+\\.developer", UaaStringUtils.constructSimpleWildcardPattern("space.*.developer"));
        assertEquals("space\\.developer", UaaStringUtils.constructSimpleWildcardPattern("space.developer"));
    }

    @Test
    void containsWildcard() {
        assertTrue(UaaStringUtils.containsWildcard("space.*.developer"));
        assertTrue(UaaStringUtils.containsWildcard("*.developer"));
        assertTrue(UaaStringUtils.containsWildcard("space.*"));
        assertFalse(UaaStringUtils.containsWildcard("space.developer"));
        assertTrue(UaaStringUtils.containsWildcard("space.*.*.developer"));
        assertTrue(UaaStringUtils.containsWildcard("*"));
    }

    @Test
    void constructSimpleWildcardPattern_matches() {
        String s1 = "space.*.developer";
        String p1 = UaaStringUtils.constructSimpleWildcardPattern(s1);
        String[] matching = new String[]{
                "space.1.developer",
                "space.13242323423423423.developer",
        };
        String[] notmatching = new String[]{
                "space.1",
                "space.1.",
                ".1.developer",
                "1.developer",
                "space.1.developers",
                "spaces.1.developer",
                "space.1.developer.test",
                "test.space.1.developer",
                "space.13242323423423423..developer",
                "space...13242323423423423...developer",
        };
        for (String m : matching) {
            String msg = "Testing [" + m + "] against [" + s1 + "]";
            assertTrue(matches(p1, m), msg);
        }
        for (String n : notmatching) {
            String msg = "Testing [" + n + "] against [" + s1 + "]";
            assertFalse(matches(p1, n), msg);
        }
    }

    @Test
    void constructSimpleWildcardPattern_includeRegExInWildcardPattern() {
        String s1 = "space.*.deve.*loper";
        String p1 = UaaStringUtils.constructSimpleWildcardPattern(s1);
        String[] notmatching = new String[]{
                "space.1.developer",
                "space.13242323423423423.developer",
                "space.1",
                "space.1.",
                ".1.developer",
                "1.developer",
                "space.1.developers",
                "spaces.1.developer",
                "space.1.developer.test",
                "test.space.1.developer",
                "space.13242323423423423..developer",
                "space...13242323423423423...developer",
        };
        for (String n : notmatching) {
            String msg = "Testing [" + n + "] against [" + s1 + "]";
            assertFalse(matches(p1, n), msg);
        }
    }

    @Test
    void constructSimpleWildcardPattern_beginningWildcardPattern() {
        String s1 = "*.*.developer";
        String p1 = UaaStringUtils.constructSimpleWildcardPattern(s1);
        String[] matching = new String[]{
                "space.1.developer",
                "space.13242323423423423.developer",
        };
        String[] notmatching = new String[]{
                "space.1",
                "space.1.",
                ".1.developer",
                "1.developer",
                "space.1.developers",
                "space.1.developer.test",
                "test.space.1.developer",
                "space.13242323423423423..developer",
                "space...13242323423423423...developer",
        };
        for (String m : matching) {
            String msg = "Testing [" + m + "] against [" + s1 + "]";
            assertTrue(matches(p1, m), msg);
        }
        for (String n : notmatching) {
            String msg = "Testing [" + n + "] against [" + s1 + "]";
            assertFalse(matches(p1, n), msg);
        }
    }

    @Test
    void constructSimpleWildcardPattern_allWildcardPattern() {
        String s1 = "*.*.*";
        String p1 = UaaStringUtils.constructSimpleWildcardPattern(s1);
        String[] matching = new String[]{
                "space.1.developer",
                "space.13242323423423423.developer",
        };
        String[] notmatching = new String[]{
                "space.1",
                "space.1.",
                ".1.developer",
                "1.developer",
                "space.1.developers.",
                "space.1.developer.test",
                "test.space.1.developer",
                "space.13242323423423423..developer",
                "space...13242323423423423...developer",
        };
        for (String m : matching) {
            String msg = "Testing [" + m + "] against [" + s1 + "]";
            assertTrue(matches(p1, m), msg);
        }
        for (String n : notmatching) {
            String msg = "Testing [" + n + "] against [" + s1 + "]";
            assertFalse(matches(p1, n), msg);
        }
    }

    @Test
    void convertISO8859_1_to_UTF_8() {
        String s = new String(new char[]{'a', '\u0000'});
        String a = UaaStringUtils.convertISO8859_1_to_UTF_8(s);
        assertEquals(s, a);
        assertEquals('\u0000', a.toCharArray()[1]);
    }

    @Test
    void retainAllMatches() {
        assertThat(
                UaaStringUtils.retainAllMatches(
                        Arrays.asList("saml.group.1",
                                "saml.group.2",
                                "saml.group1.3"),
                        Collections.singletonList("saml.group.1")
                ),
                containsInAnyOrder("saml.group.1")
        );


        assertThat(
                UaaStringUtils.retainAllMatches(
                        Arrays.asList("saml.group.1",
                                "saml.group.2",
                                "saml.group1.3"),
                        Collections.singletonList("saml.group.*")
                ),
                containsInAnyOrder("saml.group.1", "saml.group.2")
        );

        assertThat(
                UaaStringUtils.retainAllMatches(
                        Arrays.asList("saml.group.1",
                                "saml.group.2",
                                "saml.group1.3",
                                "saml.group1.3.1"),
                        Collections.singletonList("saml.group*.*")
                ),
                containsInAnyOrder("saml.group.1", "saml.group.2", "saml.group1.3", "saml.group1.3.1")
        );


        assertThat(
                UaaStringUtils.retainAllMatches(
                        Arrays.asList("saml-group-1",
                                "saml-group-2",
                                "saml-group1-3"),
                        Collections.singletonList("saml-group-*")
                ),
                containsInAnyOrder("saml-group-1", "saml-group-2")
        );

        assertThat(
                UaaStringUtils.retainAllMatches(
                        Arrays.asList("saml-group-1",
                                "saml-group-2",
                                "saml-group1-3"),
                        Collections.singletonList("saml-*-*")
                ),
                containsInAnyOrder("saml-group-1", "saml-group-2", "saml-group1-3")
        );

        assertThat(
                UaaStringUtils.retainAllMatches(
                        Arrays.asList("saml-group-1",
                                "saml-group-2",
                                "saml-group1-3"),
                        Collections.singletonList("saml-*")
                ),
                containsInAnyOrder("saml-group-1", "saml-group-2", "saml-group1-3")
        );

        assertThat(
                UaaStringUtils.retainAllMatches(
                        Arrays.asList("saml.group.1",
                                "saml.group.2",
                                "saml.group1.3"),
                        Collections.singletonList("saml.grou*.*")
                ),
                containsInAnyOrder("saml.group.1", "saml.group.2", "saml.group1.3")
        );

        assertThat(
                UaaStringUtils.retainAllMatches(
                        Arrays.asList("saml.group.1",
                                "saml.group.2",
                                "saml.group1.3"),
                        Collections.singletonList("saml.*.1")
                ),
                containsInAnyOrder("saml.group.1")
        );

        assertThat(
                UaaStringUtils.retainAllMatches(
                        Arrays.asList("saml.group.1",
                                "saml.group.2",
                                "saml.group1.3"),
                        Collections.singletonList("*.group.*")
                ),
                containsInAnyOrder("saml.group.1", "saml.group.2")
        );

        assertThat(
                UaaStringUtils.retainAllMatches(
                        Arrays.asList("saml.group.1",
                                "saml.group.2",
                                "saml.group1.3"),
                        Collections.singletonList("saml.group*1*")
                ),
                containsInAnyOrder("saml.group.1", "saml.group1.3")
        );
    }

    @Test
    void toJsonString() {
        assertEquals("Y1sPgF\\\"Yj4xYZ\\\"", UaaStringUtils.toJsonString("Y1sPgF\"Yj4xYZ\""));
        assertNull(UaaStringUtils.toJsonString(null));
        assertEquals("", UaaStringUtils.toJsonString(""));
    }

    private static void replaceZoneVariables(IdentityZone zone) {
        String s = "https://{zone.subdomain}.domain.com/z/{zone.id}?id={zone.id}&domain={zone.subdomain}";
        String expect = String.format("https://%s.domain.com/z/%s?id=%s&domain=%s", zone.getSubdomain(), zone.getId(), zone.getId(), zone.getSubdomain());
        assertEquals(expect, UaaStringUtils.replaceZoneVariables(s, zone));
    }

    private static void checkPasswords(Map<String, ?> map) {
        for (String key : map.keySet()) {
            Object value = map.get(key);
            if (value instanceof String) {
                assertEquals("#", value);
            } else if (value instanceof Map) {
                checkPasswords((Map) value);
            }
        }
    }

    private static boolean matches(String pattern, String value) {
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(value);
        return m.matches();
    }

}