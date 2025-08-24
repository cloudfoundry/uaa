package org.cloudfoundry.identity.uaa.util;

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
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
        assertThat(UaaStringUtils.nonNull()).isNull();
        assertThat(UaaStringUtils.nonNull((String) null)).isNull();
        assertThat(UaaStringUtils.nonNull(null, null)).isNull();
        assertThat(UaaStringUtils.nonNull("7")).isEqualTo("7");
        assertThat(UaaStringUtils.nonNull(null, "6")).isEqualTo("6");
        assertThat(UaaStringUtils.nonNull(null, null, "5")).isEqualTo("5");
        assertThat(UaaStringUtils.nonNull(null, null, "1", "2")).isEqualTo("1");
        assertThat(UaaStringUtils.nonNull(null, null, null, "2")).isEqualTo("2");
    }

    @Test
    void replace_zone_variables() {
        replaceZoneVariables(IdentityZone.getUaa());
        IdentityZone zone = ModelTestUtils.identityZone("otherId", "otherDomain");
        replaceZoneVariables(zone);
    }

    @Test
    void camelToUnderscore() {
        assertThat(UaaStringUtils.camelToUnderscore("testCamelCase")).isEqualTo("test_camel_case");
        assertThat(UaaStringUtils.camelToUnderscore("testcamelcase")).isEqualTo("testcamelcase");
        assertThat(UaaStringUtils.camelToUnderscore("test_camel_case")).isEqualTo("test_camel_case");
        assertThat(UaaStringUtils.camelToUnderscore("test_Camel_Case")).isEqualTo("test_camel_case");
    }

    @Test
    void getErrorName() {
        assertThat(UaaStringUtils.getErrorName(new IllegalArgumentException())).isEqualTo("illegal_argument");
        assertThat(UaaStringUtils.getErrorName(new NullPointerException())).isEqualTo("null_pointer");
    }

    @Test
    void hidePasswords() {
        Map<String, ?> result = UaaStringUtils.hidePasswords(map);
        checkPasswords(result);

        map.put("fail", "reason");
        result = UaaStringUtils.hidePasswords(map);
        assertThat(map).containsEntry("fail", "reason");
        result.remove("fail");
        checkPasswords(result);

        Properties presult = UaaStringUtils.hidePasswords(properties);
        checkPasswords(new HashMap(presult));

        properties.put("fail", "reason");
        presult = UaaStringUtils.hidePasswords(properties);
        assertThat(presult).containsEntry("fail", "reason");
        presult.remove("fail");
        checkPasswords(new HashMap(presult));
    }

    @Test
    void escapeRegExCharacters() {
        assertThat(matches(UaaStringUtils.escapeRegExCharacters(".*"), ".*")).isTrue();
        assertThat(matches(UaaStringUtils.escapeRegExCharacters(".*"), ".some other string")).isFalse();
        assertThat(matches(UaaStringUtils.escapeRegExCharacters("x"), "x")).isTrue();
        assertThat(matches(UaaStringUtils.escapeRegExCharacters("x*x"), "x*x")).isTrue();
        assertThat(UaaStringUtils.escapeRegExCharacters("\\")).isEqualTo("\\\\");
        assertThat(UaaStringUtils.escapeRegExCharacters("[")).isEqualTo("\\[");
    }

    @Test
    void constructSimpleWildcardPattern() {
        assertThat(UaaStringUtils.constructSimpleWildcardPattern("space.*.developer")).isEqualTo("space\\.[^\\\\.]+\\.developer");
        assertThat(UaaStringUtils.constructSimpleWildcardPattern("space.developer")).isEqualTo("space\\.developer");
    }

    @Test
    void containsWildcard() {
        assertThat(UaaStringUtils.containsWildcard("space.*.developer")).isTrue();
        assertThat(UaaStringUtils.containsWildcard("*.developer")).isTrue();
        assertThat(UaaStringUtils.containsWildcard("space.*")).isTrue();
        assertThat(UaaStringUtils.containsWildcard("space.developer")).isFalse();
        assertThat(UaaStringUtils.containsWildcard("space.*.*.developer")).isTrue();
        assertThat(UaaStringUtils.containsWildcard("*")).isTrue();
        assertThat(UaaStringUtils.containsWildcard(null)).isFalse();
    }

    @Test
    void constructWildcards() {
        assertThat(UaaStringUtils.constructWildcards(List.of())).isEmpty();
        assertThat(UaaStringUtils.constructWildcards(List.of("any"))).doesNotContain(Pattern.compile("any"));
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
            assertThat(matches(p1, m)).as(msg).isTrue();
        }
        for (String n : notmatching) {
            String msg = "Testing [" + n + "] against [" + s1 + "]";
            assertThat(matches(p1, n)).as(msg).isFalse();
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
            assertThat(matches(p1, n)).as(msg).isFalse();
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
            assertThat(matches(p1, m)).as(msg).isTrue();
        }
        for (String n : notmatching) {
            String msg = "Testing [" + n + "] against [" + s1 + "]";
            assertThat(matches(p1, n)).as(msg).isFalse();
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
            assertThat(matches(p1, m)).as(msg).isTrue();
        }
        for (String n : notmatching) {
            String msg = "Testing [" + n + "] against [" + s1 + "]";
            assertThat(matches(p1, n)).as(msg).isFalse();
        }
    }

    @Test
    void convertISO8859_1_to_UTF_8() {
        String s = new String(new char[]{'a', '\u0000'});
        String a = UaaStringUtils.convertISO8859_1_to_UTF_8(s);
        assertThat(a).isEqualTo(s);
        assertThat(a.toCharArray()[1]).isEqualTo('\u0000');
        assertThat(UaaStringUtils.convertISO8859_1_to_UTF_8(null)).isNull();
    }

    @Test
    void retainAllMatches() {
        assertThat(UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                        "saml.group.2",
                        "saml.group1.3"),
                Collections.singletonList("saml.group.1")
        )).contains("saml.group.1");

        assertThat(UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                        "saml.group.2",
                        "saml.group1.3"),
                Collections.singletonList("saml.group.*")
        )).contains("saml.group.1", "saml.group.2");

        assertThat(UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                        "saml.group.2",
                        "saml.group1.3",
                        "saml.group1.3.1"),
                Collections.singletonList("saml.group*.*")
        )).contains("saml.group.1", "saml.group.2", "saml.group1.3", "saml.group1.3.1");

        assertThat(UaaStringUtils.retainAllMatches(
                Arrays.asList("saml-group-1",
                        "saml-group-2",
                        "saml-group1-3"),
                Collections.singletonList("saml-group-*")
        )).contains("saml-group-1", "saml-group-2");

        assertThat(UaaStringUtils.retainAllMatches(
                Arrays.asList("saml-group-1",
                        "saml-group-2",
                        "saml-group1-3"),
                Collections.singletonList("saml-*-*")
        )).contains("saml-group-1", "saml-group-2", "saml-group1-3");

        assertThat(UaaStringUtils.retainAllMatches(
                Arrays.asList("saml-group-1",
                        "saml-group-2",
                        "saml-group1-3"),
                Collections.singletonList("saml-*")
        )).contains("saml-group-1", "saml-group-2", "saml-group1-3");

        assertThat(UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                        "saml.group.2",
                        "saml.group1.3"),
                Collections.singletonList("saml.grou*.*")
        )).contains("saml.group.1", "saml.group.2", "saml.group1.3");

        assertThat(UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                        "saml.group.2",
                        "saml.group1.3"),
                Collections.singletonList("saml.*.1")
        )).contains("saml.group.1");

        assertThat(UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                        "saml.group.2",
                        "saml.group1.3"),
                Collections.singletonList("*.group.*")
        )).contains("saml.group.1", "saml.group.2");

        assertThat(UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                        "saml.group.2",
                        "saml.group1.3"),
                Collections.singletonList("saml.group*1*")
        )).contains("saml.group.1", "saml.group1.3");
    }

    @Test
    void toJsonString() {
        assertThat(UaaStringUtils.toJsonString("Y1sPgF\"Yj4xYZ\"")).isEqualTo("Y1sPgF\\\"Yj4xYZ\\\"");
        assertThat(UaaStringUtils.toJsonString(null)).isNull();
        assertThat(UaaStringUtils.toJsonString("")).isEmpty();
    }

    @Test
    void getAuthoritiesFromStrings() {
        List<? extends GrantedAuthority> authorities = UaaStringUtils.getAuthoritiesFromStrings(null);
        assertThat(authorities).isEqualTo(Collections.emptyList());
        assertThat(UaaStringUtils.getStringsFromAuthorities(null)).isEmpty();
        authorities = UaaStringUtils.getAuthoritiesFromStrings(Collections.singletonList("uaa.user"));
        assertThat(UaaStringUtils.getStringsFromAuthorities(authorities)).isEqualTo(Set.of("uaa.user"));
    }

    @Test
    void getCleanedUserControlString() {
        assertThat(UaaStringUtils.getCleanedUserControlString(null)).isNull();
        assertThat(UaaStringUtils.getCleanedUserControlString("test\rtest")).isEqualTo("test_test");
    }

    @Test
    void getHostIfArgIsURL() {
        assertThat(UaaStringUtils.getHostIfArgIsURL("string")).isEqualTo("string");
        assertThat(UaaStringUtils.getHostIfArgIsURL("http://host/path")).isEqualTo("host");
    }

    @Test
    void containsIgnoreCase() {
        assertThat(UaaStringUtils.containsIgnoreCase(Arrays.asList("one", "two"), "one")).isTrue();
        assertThat(UaaStringUtils.containsIgnoreCase(Arrays.asList("one", "two"), "any")).isFalse();
    }

    @ParameterizedTest
    @NullAndEmptySource
    void isNullOrEmpty_ShouldReturnTrue(final String input) {
        assertThat(UaaStringUtils.isNullOrEmpty(input)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    void isNotEmpty_ShouldReturnFalse(final String input) {
        assertThat(UaaStringUtils.isNotEmpty(input)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {" ", "  ", "\t", "\n", "abc"})
    void isNullOrEmpty_ShouldReturnFalse(final String input) {
        assertThat(UaaStringUtils.isNullOrEmpty(input)).isFalse();
    }

    @Test
    void getMapFromProperties() {
        Properties props = new Properties();
        props.put("pre.key", "value");
        Map<String, Object> objectMap = UaaStringUtils.getMapFromProperties(props, "pre.");
        assertThat(objectMap).containsEntry("key", "value")
                .doesNotContainKey("pre.key");
    }

    @Test
    void getSafeParameterValue() {
        assertThat(UaaStringUtils.getSafeParameterValue(new String[]{"test"})).isEqualTo("test");
        assertThat(UaaStringUtils.getSafeParameterValue(new String[]{"  "})).isEmpty();
        assertThat(UaaStringUtils.getSafeParameterValue(new String[]{})).isEmpty();
        assertThat(UaaStringUtils.getSafeParameterValue(null)).isEmpty();
    }

    @Test
    void getArrayDefaultValue() {
        assertThat(UaaStringUtils.getValuesOrDefaultValue(Set.of("1", "2"), "1").stream().sorted().toList())
                .isEqualTo(Stream.of("1", "2").sorted().toList());
        assertThat(UaaStringUtils.getValuesOrDefaultValue(Set.of(), "1")).isEqualTo(List.of("1"));
        assertThat(UaaStringUtils.getValuesOrDefaultValue(null, "1")).isEqualTo(List.of("1"));
    }

    @Test
    void validateInput() {
        assertThat(UaaStringUtils.getValidatedString("foo")).isEqualTo("foo");
    }

    @ParameterizedTest
    @ValueSource(strings = {"\0", "", "\t", "\n", "\r"})
    void alertOnInvlidInput(String input) {
        assertThatThrownBy(() -> UaaStringUtils.getValidatedString(input))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static void replaceZoneVariables(IdentityZone zone) {
        String s = "https://{zone.subdomain}.domain.com/z/{zone.id}?id={zone.id}&domain={zone.subdomain}";
        String expect = "https://%s.domain.com/z/%s?id=%s&domain=%s".formatted(zone.getSubdomain(), zone.getId(), zone.getId(), zone.getSubdomain());
        assertThat(UaaStringUtils.replaceZoneVariables(s, zone)).isEqualTo(expect);
    }

    private static void checkPasswords(Map<String, ?> map) {
        for (String key : map.keySet()) {
            Object value = map.get(key);
            if (value instanceof String) {
                assertThat(value).isEqualTo("#");
            } else if (value instanceof Map map1) {
                checkPasswords(map1);
            }
        }
    }

    private static boolean matches(String pattern, String value) {
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(value);
        return m.matches();
    }
}
