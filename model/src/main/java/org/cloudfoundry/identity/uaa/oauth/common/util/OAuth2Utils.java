package org.cloudfoundry.identity.uaa.oauth.common.util;

import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 utils
 */
public abstract class OAuth2Utils {

    private OAuth2Utils() {
    }

    /**
     * Constant to use while parsing and formatting parameter maps for OAuth2 requests
     */
    public static final String CLIENT_ID = "client_id";

    /**
     * Constant to use while parsing and formatting parameter maps for OAuth2 requests
     */
    public static final String STATE = "state";

    /**
     * Constant to use while parsing and formatting parameter maps for OAuth2 requests
     */
    public static final String SCOPE = "scope";

    /**
     * Constant to use while parsing and formatting parameter maps for OAuth2 requests
     */
    public static final String REDIRECT_URI = "redirect_uri";

    /**
     * Constant to use while parsing and formatting parameter maps for OAuth2 requests
     */
    public static final String RESPONSE_TYPE = "response_type";

    /**
     * Constant to use while parsing and formatting parameter maps for OAuth2 requests
     */
    public static final String USER_OAUTH_APPROVAL = "user_oauth_approval";

    /**
     * Constant to use as a prefix for scope approval
     */
    public static final String SCOPE_PREFIX = "scope.";

    /**
     * Constant to use while parsing and formatting parameter maps for OAuth2 requests
     */
    public static final String GRANT_TYPE = "grant_type";

    /**
     * Constant to use in authorization code flow
     */
    public static final String CODE = "code";

    /**
     * Parses a string parameter value into a set of strings.
     * 
     * @param values The values of the set.
     * @return The set.
     */
    public static Set<String> parseParameterList(String values) {
        Set<String> result = new TreeSet<>();
        if (values != null && values.trim().length() > 0) {
            // the spec says the scope is separated by spaces
            String[] tokens = values.split("[\\s+]");
            result.addAll(Arrays.asList(tokens));
        }
        return result;
    }

    /**
     * Formats a set of string values into a format appropriate for sending as a single-valued form value.
     * 
     * @param value The value of the parameter.
     * @return The value formatted for form submission etc, or null if the input is empty
     */
    public static String formatParameterList(Collection<String> value) {
        return value == null ? null : StringUtils.collectionToDelimitedString(value, " ");
    }

    /**
     * Extract a map from a query string.
     * 
     * @param query a query (or fragment) string from a URI
     * @return a Map of the values in the query
     */
    public static Map<String, String> extractMap(String query) {
        Map<String, String> map = new HashMap<>();
        Properties properties = StringUtils.splitArrayElementsIntoProperties(
                StringUtils.delimitedListToStringArray(query, "&"), "=");
        if (properties != null) {
            for (Map.Entry<Object, Object> entry : properties.entrySet()) {
                map.put(entry.getKey().toString(), entry.getValue().toString());
            }
        }
        return map;
    }
}
