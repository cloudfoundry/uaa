/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
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

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.ObjectUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public final class UaaStringUtils {

    public static final String ZONE_VAR_ID = "{zone.id}";
    public static final String ZONE_VAR_SUBDOMAIN = "{zone.subdomain}";

    public static final String ISO_8859_1 = "ISO-8859-1";
    public static final String UTF_8 = "UTF-8";

    private static final Pattern CAML_PATTERN = Pattern.compile("([a-z])([A-Z])");
    private static final Pattern CTRL_PATTERN = Pattern.compile("[\n\r\t]");
    private static final Pattern ALL_CTRL_PATTERN = Pattern.compile("\\p{C}");

    public static final String EMPTY_STRING = "";

    public static final String DEFAULT_UAA_URL = "http://localhost:8080/uaa";

    private UaaStringUtils() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static String replaceZoneVariables(String s, IdentityZone zone) {
        return s.replace(ZONE_VAR_ID, zone.getId()).replace(ZONE_VAR_SUBDOMAIN, zone.getSubdomain());
    }

    public static String nonNull(String... s) {
        if (s != null) {
            for (String str : s) {
                if (str != null) {
                    return str;
                }
            }
        }
        return null;
    }

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
        result = CAML_PATTERN.matcher(result).replaceAll("$1_$2");
        result = result.replace(".", "_");
        result = result.toLowerCase(Locale.US);
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
        Map<String, Object> result = new LinkedHashMap<>(map);
        for (Map.Entry<String, ?> entry : map.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
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
        if (hasText(s)) {
            return !escapeRegExCharacters(s).equals(constructSimpleWildcardPattern(s));
        }
        return false;
    }

    /**
     * Escapes all regular expression patterns in a string so that when
     * using the string itself in a regular expression, only an exact literal match will
     * return true. For example, the string ".*" will not match any string, it will only
     * match ".*". The value ".*" when escaped will be "\.\*"
     *
     * @param s - the string for which we need to escape regular expression constructs
     * @return a regular expression string that will only match exact literals
     */
    public static String escapeRegExCharacters(String s) {
        return escapeRegExCharacters(s, "([^a-zA-Z0-9 ])");
    }

    /**
     * Escapes all regular expression patterns in a string so that when
     * using the string itself in a regular expression, only an exact literal match will
     * return true.
     *
     * @param s       - the string for which we need to escape regular expression constructs
     * @param pattern - the pattern containing the characters we wish to remain string literals
     * @return a regular expression string that will only match exact literals
     */
    public static String escapeRegExCharacters(String s, String pattern) {
        return s.replaceAll(pattern, "\\\\$1");
    }

    /**
     * Returns a pattern that does a single level regular expression match where
     * the * character is a wildcard until it encounters the next literal
     *
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

    public static Set<Pattern> constructWildcards(Collection<String> wildcardStrings, UnaryOperator<String> replace) {
        Set<Pattern> wildcards = new HashSet<>();
        for (String wildcard : wildcardStrings) {
            String pattern = replace.apply(wildcard);
            wildcards.add(Pattern.compile(pattern));
        }
        return wildcards;
    }

    public static boolean matches(Iterable<Pattern> wildcards, String scope) {
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
     * @param prefix     the prefix to strip from key names
     * @return a map of String values
     */
    public static Map<String, Object> getMapFromProperties(Properties properties, String prefix) {
        Map<String, Object> result = new HashMap<>();
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
        } catch (MalformedURLException ignored) {
        }
        return arg;
    }

    private static boolean isPassword(String key) {
        key = key.toLowerCase(Locale.US);
        return
                key.endsWith("password") ||
                        key.endsWith("secret") ||
                        key.endsWith("signing-key") ||
                        key.contains("serviceproviderkey");
    }

    public static Set<String> getStringsFromAuthorities(Collection<? extends GrantedAuthority> authorities) {
        if (authorities == null) {
            return Collections.emptySet();
        }
        Set<String> result = new HashSet<>();
        for (GrantedAuthority authority : authorities) {
            result.add(authority.getAuthority());
        }
        return result;
    }

    public static List<? extends GrantedAuthority> getAuthoritiesFromStrings(Collection<String> authorities) {
        if (authorities == null) {
            return Collections.emptyList();
        }

        List<GrantedAuthority> result = new LinkedList<>();
        for (String s : authorities) {
            result.add(new SimpleGrantedAuthority(s));
        }
        return result;
    }

    public static boolean containsIgnoreCase(Iterable<String> list, String findMe) {
        for (String s : list) {
            if (findMe.equalsIgnoreCase(s)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isNullOrEmpty(final String input) {
        return input == null || input.length() == 0;
    }

    public static boolean isEmpty(final String input) {
        return input == null || input.length() == 0;
    }

    public static boolean isNotEmpty(final String input) {
        return !isNullOrEmpty(input);
    }

    public static String convertISO8859_1_to_UTF_8(String s) {
        if (s == null) {
            return null;
        } else {
            return new String(s.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
        }
    }

    public static String toJsonString(String s) {
        if (s == null) {
            return null;
        }
        String result = JsonUtils.writeValueAsString(s);
        return result.substring(1, result.length() - 1);
    }

    public static String getCleanedUserControlString(String input, String replacement) {
        if (isEmpty(input)) {
            return null;
        }
        return CTRL_PATTERN.matcher(input).replaceAll(replacement);

    }

    public static String getCleanedUserControlString(String input) {
        return getCleanedUserControlString(input, "_");
    }

    public static String getValidatedString(String input) {
        if (!isNullOrEmpty(input) && !ALL_CTRL_PATTERN.matcher(input).find()) {
            return input;
        }
        throw new IllegalArgumentException("Invalid input");
    }

    public static String getSafeParameterValue(String[] value) {
        if (null == value || value.length < 1) {
            return EMPTY_STRING;
        }
        return hasText(value[0]) ? value[0] : EMPTY_STRING;
    }

    public static boolean hasText(String str) {
        return (str != null && !str.isBlank());
    }

    public static List<String> getValuesOrDefaultValue(Set<String> values, String defaultValue) {
        if (ObjectUtils.isEmpty(values)) {
            return List.of(defaultValue);
        } else {
            return new ArrayList<>(values);
        }
    }
}
