package org.cloudfoundry.identity.uaa.util;

import org.assertj.core.api.Assertions;
import org.cloudfoundry.identity.uaa.test.ModelTestUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.core.GrantedAuthority;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasEntry;
import static org.junit.jupiter.api.Assertions.*;

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
        map.put("serviceproviderkey", "key");

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
        IdentityZone zone = ModelTestUtils.identityZone("otherId", "otherDomain");
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

        map.put("fail", "reason");
        result = UaaStringUtils.hidePasswords(map);
        assertThat(map, hasEntry("fail", "reason"));
        result.remove("fail");
        checkPasswords(result);

        Properties presult = UaaStringUtils.hidePasswords(properties);
        checkPasswords(new HashMap(presult));

        properties.put("fail", "reason");
        presult = UaaStringUtils.hidePasswords(properties);
        assertThat(presult, hasEntry("fail", "reason"));
        presult.remove("fail");
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
        assertFalse(UaaStringUtils.containsWildcard(null));
    }

    @Test
    void constructWildcards() {
        assertEquals(Set.of(), UaaStringUtils.constructWildcards(Collections.EMPTY_LIST));
        assertFalse(UaaStringUtils.constructWildcards(Collections.singletonList("any")).contains("any"));
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
        assertNull(UaaStringUtils.convertISO8859_1_to_UTF_8(null));
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

    @Test
    void testGetAuthoritiesFromStrings() {
        List<? extends GrantedAuthority> authorities = UaaStringUtils.getAuthoritiesFromStrings(null);
        assertEquals(Collections.EMPTY_LIST, authorities);
        assertEquals(0, UaaStringUtils.getStringsFromAuthorities(null).size());
        authorities = UaaStringUtils.getAuthoritiesFromStrings(Collections.singletonList("uaa.user"));
        assertEquals(Set.of("uaa.user"), UaaStringUtils.getStringsFromAuthorities(authorities));
    }

    @Test
    void getCleanedUserControlString() {
        assertNull(UaaStringUtils.getCleanedUserControlString(null));
        assertEquals("test_test", UaaStringUtils.getCleanedUserControlString("test\rtest"));
    }

    @Test
    void getHostIfArgIsURL() {
        assertEquals("string", UaaStringUtils.getHostIfArgIsURL("string"));
        assertEquals("host", UaaStringUtils.getHostIfArgIsURL("http://host/path"));
    }

    @Test
    void containsIgnoreCase() {
        assertTrue(UaaStringUtils.containsIgnoreCase(Arrays.asList("one", "two"), "one"));
        assertFalse(UaaStringUtils.containsIgnoreCase(Arrays.asList("one", "two"), "any"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void isNullOrEmpty_ShouldReturnTrue(final String input) {
        Assertions.assertThat(UaaStringUtils.isNullOrEmpty(input)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    void isNotEmpty_ShouldReturnFalse(final String input) {
        Assertions.assertThat(UaaStringUtils.isNotEmpty(input)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = { " ", "  ", "\t", "\n", "abc" })
    void isNullOrEmpty_ShouldReturnFalse(final String input) {
        Assertions.assertThat(UaaStringUtils.isNullOrEmpty(input)).isFalse();
    }

    @Test
    void getMapFromProperties() {
        Properties properties = new Properties();
        properties.put("pre.key", "value");
        Map<String, ?> objectMap = UaaStringUtils.getMapFromProperties(properties, "pre.");
        assertThat(objectMap, hasEntry("key", "value"));
    }

    @Test
    void getSafeParameterValue() {
        assertEquals("test", UaaStringUtils.getSafeParameterValue(new String[] {"test"}));
        assertEquals("", UaaStringUtils.getSafeParameterValue(new String[] {"  "}));
        assertEquals("", UaaStringUtils.getSafeParameterValue(new String[] {}));
        assertEquals("", UaaStringUtils.getSafeParameterValue(null));
    }

    @Test
    void getArrayDefaultValue() {
        assertEquals(List.of("1", "2").stream().sorted().collect(Collectors.toList()),
            UaaStringUtils.getValuesOrDefaultValue(Set.of("1", "2"), "1").stream().sorted().collect(Collectors.toList()));
        assertEquals(List.of("1"), UaaStringUtils.getValuesOrDefaultValue(Set.of(), "1"));
        assertEquals(List.of("1"), UaaStringUtils.getValuesOrDefaultValue(null, "1"));
    }

    @Test
    void validateInput() {
        assertEquals("foo", UaaStringUtils.getValidatedString("foo"));
    }

    @ParameterizedTest
    @ValueSource(strings = { "\0", "", "\t", "\n", "\r" })
    void alertOnInvlidInput(String input) {
        assertThrows(IllegalArgumentException.class, () -> UaaStringUtils.getValidatedString(input));
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