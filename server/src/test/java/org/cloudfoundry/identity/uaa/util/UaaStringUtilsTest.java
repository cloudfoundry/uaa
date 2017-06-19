package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class UaaStringUtilsTest {

    private Map<String, Object> map;
    private Properties properties;

    @Before
    public void setUp() {
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

    @After
    public void clear() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void non_null() throws Exception {
        assertNull(UaaStringUtils.nonNull(null));
        assertEquals("1", UaaStringUtils.nonNull("1"));
        assertEquals("1", UaaStringUtils.nonNull(null,"1"));
        assertEquals("1", UaaStringUtils.nonNull(null,null,"1"));
        assertEquals("1", UaaStringUtils.nonNull(null,null, "1", "2"));
        assertEquals("2", UaaStringUtils.nonNull(null,null, null, "2"));
    }
    @Test
    public void replace_zone_variables() throws Exception {
        test_replace_zone_variables(IdentityZone.getUaa());
        IdentityZone zone = MultitenancyFixture.identityZone("otherId", "otherDomain");
        test_replace_zone_variables(zone);
    }

    public void test_replace_zone_variables(IdentityZone zone) throws Exception {
        String s = "https://{zone.subdomain}.domain.com/z/{zone.id}?id={zone.id}&domain={zone.subdomain}";
        String expect = String.format("https://%s.domain.com/z/%s?id=%s&domain=%s", zone.getSubdomain(), zone.getId(), zone.getId(), zone.getSubdomain());
        assertEquals(expect, UaaStringUtils.replaceZoneVariables(s, zone));
    }

    @Test
    public void testCamelToUnderscore() throws Exception {
        assertEquals("test_camel_case", UaaStringUtils.camelToUnderscore("testCamelCase"));
        assertEquals("testcamelcase", UaaStringUtils.camelToUnderscore("testcamelcase"));
        assertEquals("test_camel_case", UaaStringUtils.camelToUnderscore("test_camel_case"));
        assertEquals("test_camel_case", UaaStringUtils.camelToUnderscore("test_Camel_Case"));
    }

    @Test
    public void testGetErrorName() throws Exception {
        assertEquals("illegal_argument", UaaStringUtils.getErrorName(new IllegalArgumentException()));
        assertEquals("null_pointer", UaaStringUtils.getErrorName(new NullPointerException()));
    }

    @Test
    public void testHidePasswords() throws Exception {
        Map<String,?> result = UaaStringUtils.hidePasswords(map);
        checkPasswords(result);

        Properties presult = UaaStringUtils.hidePasswords(properties);
        checkPasswords(new HashMap(presult));
    }

    private void checkPasswords(Map<String,?> map) {
        for (String key : map.keySet()) {
            Object value = map.get(key);
            if (value instanceof String) {
                assertEquals("#", (String)value);
            } else if (value instanceof Map) {
                checkPasswords((Map)value);
            }
        }
    }

    @Test
    public void testEscapeRegExCharacters() throws Exception {
        assertTrue(matches(UaaStringUtils.escapeRegExCharacters(".*"), ".*"));
        assertFalse(matches(UaaStringUtils.escapeRegExCharacters(".*"), ".some other string"));
        assertTrue(matches(UaaStringUtils.escapeRegExCharacters("x"), "x"));
        assertTrue(matches(UaaStringUtils.escapeRegExCharacters("x*x"), "x*x"));
    }

    @Test
    public void testConstructSimpleWildcardPattern() throws Exception {
        assertEquals("space\\.[^\\\\.]+\\.developer", UaaStringUtils.constructSimpleWildcardPattern("space.*.developer"));
        assertEquals("space\\.developer", UaaStringUtils.constructSimpleWildcardPattern("space.developer"));
    }

    @Test
    public void testContainsWildCard() {
        assertTrue(UaaStringUtils.containsWildcard("space.*.developer"));
        assertTrue(UaaStringUtils.containsWildcard("*.developer"));
        assertTrue(UaaStringUtils.containsWildcard("space.*"));
        assertFalse(UaaStringUtils.containsWildcard("space.developer"));
        assertTrue(UaaStringUtils.containsWildcard("space.*.*.developer"));
        assertTrue(UaaStringUtils.containsWildcard("*"));
    }

    @Test
    public void testSimpleWildcardPattern() throws Exception {
        String s1 = "space.*.developer";
        String p1 = UaaStringUtils.constructSimpleWildcardPattern(s1);
        String[] matching = new String[] {
            "space.1.developer",
            "space.13242323423423423.developer",
        };
        String[] notmatching = new String[] {
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
            String msg = "Testing ["+m+"] against ["+s1+"]";
            assertTrue(msg, matches(p1, m));
        }
        for (String n : notmatching) {
            String msg = "Testing ["+n+"] against ["+s1+"]";
            assertFalse(msg, matches(p1, n));
        }
    }

    @Test
    public void testIncludeRegExInWildcardPattern() throws Exception {
        String s1 = "space.*.deve.*loper";
        String p1 = UaaStringUtils.constructSimpleWildcardPattern(s1);
        String[] matching = new String[] {
        };
        String[] notmatching = new String[] {
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
        for (String m : matching) {
            String msg = "Testing ["+m+"] against ["+s1+"]";
            assertTrue(msg, matches(p1, m));
        }
        for (String n : notmatching) {
            String msg = "Testing ["+n+"] against ["+s1+"]";
            assertFalse(msg, matches(p1, n));
        }
    }

    @Test
    public void testBeginningWildcardPattern() throws Exception {
        String s1 = "*.*.developer";
        String p1 = UaaStringUtils.constructSimpleWildcardPattern(s1);
        String[] matching = new String[] {
            "space.1.developer",
            "space.13242323423423423.developer",
        };
        String[] notmatching = new String[] {
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
            String msg = "Testing ["+m+"] against ["+s1+"]";
            assertTrue(msg, matches(p1, m));
        }
        for (String n : notmatching) {
            String msg = "Testing ["+n+"] against ["+s1+"]";
            assertFalse(msg, matches(p1, n));
        }
    }

    @Test
    public void testAllWildcardPattern() throws Exception {
        String s1 = "*.*.*";
        String p1 = UaaStringUtils.constructSimpleWildcardPattern(s1);
        String[] matching = new String[] {
            "space.1.developer",
            "space.13242323423423423.developer",
        };
        String[] notmatching = new String[] {
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
            String msg = "Testing ["+m+"] against ["+s1+"]";
            assertTrue(msg, matches(p1, m));
        }
        for (String n : notmatching) {
            String msg = "Testing ["+n+"] against ["+s1+"]";
            assertFalse(msg, matches(p1, n));
        }
    }

    @Test
    public void test_null_utf_string() {
        String s = new String(new char[] {'a','\u0000'});
        String a = UaaStringUtils.convertISO8859_1_to_UTF_8(s);
        assertEquals(s,a);
        assertEquals('\u0000', a.toCharArray()[1]);
    }

    @Test
    public void test_retainAllMatches() {
        assertThat(
            UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                              "saml.group.2",
                              "saml.group1.3"),
                Arrays.asList("saml.group.1")
            ),
            containsInAnyOrder("saml.group.1")
        );


        assertThat(
            UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                              "saml.group.2",
                              "saml.group1.3"),
                Arrays.asList("saml.group.*")
            ),
            containsInAnyOrder("saml.group.1", "saml.group.2")
        );

        assertThat(
            UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                              "saml.group.2",
                              "saml.group1.3",
                              "saml.group1.3.1"),
                Arrays.asList("saml.group*.*")
            ),
            containsInAnyOrder("saml.group.1", "saml.group.2", "saml.group1.3", "saml.group1.3.1")
        );


        assertThat(
            UaaStringUtils.retainAllMatches(
                Arrays.asList("saml-group-1",
                              "saml-group-2",
                              "saml-group1-3"),
                Arrays.asList("saml-group-*")
            ),
            containsInAnyOrder("saml-group-1", "saml-group-2")
        );

        assertThat(
            UaaStringUtils.retainAllMatches(
                Arrays.asList("saml-group-1",
                              "saml-group-2",
                              "saml-group1-3"),
                Arrays.asList("saml-*-*")
            ),
            containsInAnyOrder("saml-group-1", "saml-group-2", "saml-group1-3")
        );

        assertThat(
            UaaStringUtils.retainAllMatches(
                Arrays.asList("saml-group-1",
                              "saml-group-2",
                              "saml-group1-3"),
                Arrays.asList("saml-*")
            ),
            containsInAnyOrder("saml-group-1", "saml-group-2", "saml-group1-3")
        );

        assertThat(
            UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                              "saml.group.2",
                              "saml.group1.3"),
                Arrays.asList("saml.grou*.*")
            ),
            containsInAnyOrder("saml.group.1", "saml.group.2", "saml.group1.3")
        );

        assertThat(
            UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                              "saml.group.2",
                              "saml.group1.3"),
                Arrays.asList("saml.*.1")
            ),
            containsInAnyOrder("saml.group.1")
        );

        assertThat(
            UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                              "saml.group.2",
                              "saml.group1.3"),
                Arrays.asList("*.group.*")
            ),
            containsInAnyOrder("saml.group.1", "saml.group.2")
        );

        assertThat(
            UaaStringUtils.retainAllMatches(
                Arrays.asList("saml.group.1",
                              "saml.group.2",
                              "saml.group1.3"),
                Arrays.asList("saml.group*1*")
            ),
            containsInAnyOrder("saml.group.1", "saml.group1.3")
        );
    }

    private boolean matches(String pattern, String value) {
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(value);
        return m.matches();
    }



    public void testGetMapFromProperties() throws Exception {
        Map<String,?> result = UaaStringUtils.getMapFromProperties(properties, "test.");
        assertEquals(3, result.size());
    }

}