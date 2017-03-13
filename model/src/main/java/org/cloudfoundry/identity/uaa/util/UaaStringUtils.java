/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.util;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * @author Dave Syer
 *
 */
public class UaaStringUtils {

    public static final String ISO_8859_1 = "ISO-8859-1";
    public static final String UTF_8 = "UTF-8";

    /**
     * Convert a string from camel case to underscores, also replacing periods
     * with underscores (so for example a fully
     * qualified Java class name gets underscores everywhere).
     *
     * @param value a camel case String
     * @return the same value with camels comverted to underscores
     */
    public static String camelToUnderscore(String value) {
        String result = value.replace(" ", "_");
        result = result.replaceAll("([a-z])([A-Z])", "$1_$2");
        result = result.replace(".", "_");
        result = result.toLowerCase();
        return result;
    }

    public static String getErrorName(Exception e) {
        String name = e.getClass().getSimpleName();
        name = UaaStringUtils.camelToUnderscore(name);
        if (name.endsWith("_exception")) {
            name = name.substring(0, name.lastIndexOf("_exception"));
        }
        return name;
    }

    /**
     * Hide the passwords and secrets in a config map (e.g. for logging).
     *
     * @param map a map with String keys (e.g. Properties) and String or nested
     *            map values
     * @return new properties with no plaintext passwords and secrets
     */
    public static Map<String, ?> hidePasswords(Map<String, ?> map) {
        Map<String, Object> result = new LinkedHashMap<String, Object>();
        result.putAll(map);
        for (String key : map.keySet()) {
            Object value = map.get(key);
            if (value instanceof String) {
                if (isPassword(key)) {
                    result.put(key, "#");
                }
            } else if (value instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, ?> bare = (Map<String, ?>) value;
                result.put(key, hidePasswords(bare));
            }
        }
        return result;
    }

    /**
     * Hide the values in a config map (e.g. for logging).
     *
     * @param map a map with String keys (e.g. Properties) and String or nested
     *            map values
     * @return new properties with no plaintext passwords and secrets
     */
    public static Map<String, ?> redactValues(Map<String, ?> map) {
        Map<String, Object> result = new LinkedHashMap<String, Object>();
        result.putAll(map);
        for (String key : map.keySet()) {
            Object value = map.get(key);
            if (value instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, ?> bare = (Map<String, ?>) value;
                result.put(key, redactValues(bare));
            } else if (value instanceof String) {
                    result.put(key, "<redacted>");
            }
        }
        return result;
    }

    /**
     * @param properties the properties with potential password values
     * @return new properties with no plaintext passwords
     */
    public static Properties hidePasswords(Properties properties) {
        Properties result = new Properties();
        result.putAll(properties);
        for (String key : properties.stringPropertyNames()) {
            if (isPassword(key)) {
                result.put(key, "#");
            }
        }
        return result;
    }

    public static Set<String> retainAllMatches(Collection<String> values, Collection<String> whitelist) {
        Set<Pattern> regExPatterns = UaaStringUtils.constructWildcards(new HashSet<>(whitelist), UaaStringUtils::constructSimpleWildcardPatternWithAnyCharDelimiter);
        return values.stream().filter(s -> matches(regExPatterns, s)).collect(Collectors.toSet());
    }

    public static boolean containsWildcard(String s) {
        if (StringUtils.hasText(s)) {
            return !escapeRegExCharacters(s).equals(constructSimpleWildcardPattern(s));
        }
        return false;
     }

    /**
     * Escapes all regular expression patterns in a string so that when
     * using the string itself in a regular expression, only an exact literal match will
     * return true. For example, the string ".*" will not match any string, it will only
     * match ".*". The value ".*" when escaped will be "\.\*"
     * @param s - the string for which we need to escape regular expression constructs
     * @return a regular expression string that will only match exact literals
     */
    public static String escapeRegExCharacters(String s) {
        return escapeRegExCharacters(s, "([^a-zA-z0-9 ])");
    }

    /**
     * Escapes all regular expression patterns in a string so that when
     * using the string itself in a regular expression, only an exact literal match will
     * return true.
     * @param s - the string for which we need to escape regular expression constructs
     * @param pattern - the pattern containing the characters we wish to remain string literals
     * @return a regular expression string that will only match exact literals
     */
    public static String escapeRegExCharacters(String s, String pattern) {
        return s.replaceAll(pattern, "\\\\$1");
    }

    /**
     * Returns a pattern that does a single level regular expression match where
     * the * character is a wildcard until it encounters the next literal
     * @param s
     * @return the wildcard pattern
     */
    public static String constructSimpleWildcardPattern(String s) {
        String result = escapeRegExCharacters(s);
        //we want to match any characters between dots
        //so what we do is replace \* in our escaped string
        //with [^\\.]+
        //reference http://www.regular-expressions.info/dot.html
        return result.replace("\\*", "[^\\\\.]+");
    }

    public static String constructSimpleWildcardPatternWithAnyCharDelimiter(String s) {
        String result = escapeRegExCharacters(s);
        return result.replace("\\*", ".*");
    }


    public static Set<Pattern> constructWildcards(Collection<String> wildcardStrings) {
        return constructWildcards(wildcardStrings, UaaStringUtils::constructSimpleWildcardPattern);
    }

    public static Set<Pattern> constructWildcards(Collection<String> wildcardStrings, Function<String, String> replace) {
        Set<Pattern> wildcards = new HashSet<>();
        for (String wildcard : wildcardStrings) {
            String pattern = replace.apply(wildcard);
            wildcards.add(Pattern.compile(pattern));
        }
        return wildcards;
    }

    public static boolean matches(Set<Pattern> wildcards, String scope) {
        for (Pattern wildcard : wildcards) {
            if (wildcard.matcher(scope).matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract a Map from some properties by removing a prefix from the key
     * names.
     *
     * @param properties the properties to use
     * @param prefix the prefix to strip from key names
     * @return a map of String values
     */
    public static Map<String, ?> getMapFromProperties(Properties properties, String prefix) {
        Map<String, Object> result = new HashMap<String, Object>();
        for (String key : properties.stringPropertyNames()) {
            if (key.startsWith(prefix)) {
                String name = key.substring(prefix.length());
                result.put(name, properties.getProperty(key));
            }
        }
        return result;
    }

    public static String getHostIfArgIsURL(String arg) {

        try {
            URL uri = new URL(arg);
            return uri.getHost();
        } catch (MalformedURLException e) {
        }
        return arg;
    }

    private static boolean isPassword(String key) {
        key = key.toLowerCase();
        return
            key.endsWith("password") ||
            key.endsWith("secret") ||
            key.endsWith("signing-key") ||
            key.contains("serviceproviderkey")
            ;
    }

    public static Set<String> getStringsFromAuthorities(Collection<? extends GrantedAuthority> authorities) {
        if (authorities==null) {
            return Collections.EMPTY_SET;
        }
        Set<String> result = new HashSet<>();
        for (GrantedAuthority authority : authorities) {
            result.add(authority.getAuthority());
        }
        return result;
    }

    public static List<? extends GrantedAuthority> getAuthoritiesFromStrings(Collection<String> authorities) {
        if (authorities==null) {
            return Collections.EMPTY_LIST;
        }

        List<GrantedAuthority> result = new LinkedList<>();
        for (String s : authorities) {
            result.add(new SimpleGrantedAuthority(s));
        }
        return result;
    }

    public static boolean containsIgnoreCase(List<String> list, String findMe) {
        for (String s : list) {
            if (findMe.equalsIgnoreCase(s)) {
                return true;
            }
        }
        return false;
    }

    public static String convertISO8859_1_to_UTF_8(String s) {
        if (s==null) {
            return null;
        } else {
            return new String(s.getBytes(Charset.forName(ISO_8859_1)), Charset.forName(UTF_8));
        }
    }

}
