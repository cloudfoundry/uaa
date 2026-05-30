package org.cloudfoundry.identity.uaa.util;

import jakarta.servlet.http.Cookie;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.InvalidUrlException;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.util.StringUtils.hasLength;

public abstract class UaaUrlUtils {
    private UaaUrlUtils() {
    }

    /** Pattern that matches valid subdomains.
     *  According to <a href="https://tools.ietf.org/html/rfc3986#section-3.2.2">rfc3986 §3.2.2</a>
     */
    private static final Pattern VALID_SUBDOMAIN_PATTERN = Pattern.compile("([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])");
    private static final Logger s_logger = LoggerFactory.getLogger(
            UaaUrlUtils.class);

    private static final int MAX_URI_DECODES = 5;

    /**
     * Static resource path prefixes that should be treated as static assets.
     * These paths typically serve CSS, JavaScript, images, and font files.
     */
    private static final Set<String> STATIC_RESOURCE_PREFIXES = Set.of("/resources/", "/vendor/");

    public static String getUaaUrl(String path, IdentityZone currentIdentityZone) {
        return getUaaUrl(path, false, currentIdentityZone);
    }

    public static String getUaaUrl(String path, boolean zoneSwitchPossible, IdentityZone currentIdentityZone) {
        return getURIBuilder(path, zoneSwitchPossible, currentIdentityZone, null).build().toUriString();
    }

    public static String getUaaUrl(UriComponentsBuilder builder, boolean zoneSwitchPossible, IdentityZone currentIdentityZone) {
        return getURIBuilder(null, zoneSwitchPossible, currentIdentityZone, builder).build().toUriString();
    }

    public static String getUaaHost(IdentityZone currentIdentityZone) {
        return getURIBuilder(UaaStringUtils.EMPTY_STRING, false, currentIdentityZone, null).build().getHost();
    }

    private static UriComponentsBuilder getURIBuilder(
            String path,
            boolean zoneSwitchPossible,
            IdentityZone currentIdentityZone, UriComponentsBuilder baseBuilder) {
        UriComponentsBuilder builder = baseBuilder != null ? baseBuilder : ServletUriComponentsBuilder.fromCurrentContextPath().path(path);
        if (zoneSwitchPossible) {
            // When zone is in the path (context path contains /z/subdomain), do not add subdomain to host
            if (isZoneInRequestPath()) {
                return builder;
            }
            String host = builder.build().getHost();
            if (host != null && !currentIdentityZone.isUaa() &&
                    !host.startsWith(currentIdentityZone.getSubdomain() + ".")) {
                host = currentIdentityZone.getSubdomain() + "." + host;
                builder.host(host);
            }
        }
        return builder;
    }

    private static boolean isZoneInRequestPath() {
        try {
            if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs
                    && attrs.getRequest() != null) {
                HttpServletRequest request = attrs.getRequest();
                Object origAttr = request.getAttribute(ZonePathContextRewritingFilter.ZONE_ORIGINAL_CONTEXT_PATH);
                if (origAttr instanceof String originalContextPath) {
                    String contextPath = request.getContextPath();
                    return contextPath != null
                            && contextPath.startsWith(originalContextPath + ZonePathContextRewritingFilter.ZONE_PATH_PREFIX);
                }
            }
        } catch (IllegalStateException ignored) {
            // No request bound
        }
        return false;
    }

    /**
     * Maximum length accepted for a registered redirect URI. Inputs longer than this are rejected
     * before regex evaluation as a defence against polynomial backtracking on pathological inputs.
     * RFC 7230 limizd max URI is 8000.
     */
    private static final int MAX_REDIRECT_URI_LENGTH = 8000;

    private static final Pattern allowedRedirectUriPattern = Pattern.compile(
            "^([a-zA-Z][a-zA-Z0-9+\\*\\-.]*)://" + //URL starts with 'some-scheme://' or 'https://' or 'http*://
                    "([^:/@]{0,255}:[^/@]{0,255}@)?" + //username/password in URL — bounded, no `/`/`@` to avoid ReDoS
                    "(([a-zA-Z0-9\\-\\*\\_]+\\.){0,255}" + //subdomains (RFC1035) limited, regex backtracking disabled
                    "[a-zA-Z0-9\\-\\_]+\\.)?" +      //hostname
                    "[a-zA-Z0-9\\-]+" +              //tld
                    "((:[0-9]+)|(:\\*))?(/.*|$)"              //port and path
    );

    public static boolean isValidRegisteredRedirectUrl(String url) {
        if (hasText(url) && url.length() <= MAX_REDIRECT_URI_LENGTH) {
            return allowedRedirectUriPattern.matcher(url).matches();
        }
        return false;
    }

    public static boolean isValidSubdomain(String subdomain) {
        return VALID_SUBDOMAIN_PATTERN.matcher(subdomain).matches();
    }

    /**
     * Finds and returns a matching redirect URL according to the following logic:
     * <ul>
     * <li>If the requstedRedirectUri matches the whitelist the requestedRedirectUri is returned</li>
     * <li>If the whitelist is null or empty AND the fallbackRedirectUri is null, the requestedRedirectUri is returned - OPEN REDIRECT</li>
     * <li>If the whitelist is null or empty AND the fallbackRedirectUri is not null, the fallbackRedirectUri is returned</li>
     * </ul>
     *
     * @param redirectUris         - a whitelist collection of ant path patterns
     * @param requestedRedirectUri - the requested redirect URI, returned if whitelist matches or the fallbackRedirectUri is null
     * @param fallbackRedirectUri  - returned if non null and the requestedRedirectUri doesn't match the whitelist redirectUris
     * @return a redirect URI, either the requested or fallback as described above
     */
    public static String findMatchingRedirectUri(Collection<String> redirectUris, String requestedRedirectUri, String fallbackRedirectUri) {
        AntPathMatcher matcher = new AntPathMatcher();

        for (String pattern : ofNullable(redirectUris).orElse(emptyList())) {
            if (matcher.match(pattern, requestedRedirectUri)) {
                if ((!pattern.contains("*") && !pattern.contains("?")) || matchHost(pattern, requestedRedirectUri, matcher)) {
                    return requestedRedirectUri;
                } else {
                    s_logger.warn(
                            "The URI pattern matched but the hostname pattern did not. Denying the requested redirect URI: whitelisted-pattern='{}' requested-redirect-uri='{}'",
                            pattern, requestedRedirectUri);
                }
            }
        }

        return ofNullable(fallbackRedirectUri).orElse(requestedRedirectUri);
    }

    /**
     * Retrieve hostname parts from <code>uriPattern</code> and
     * <code>requestedUri</code>, then do Ant path match of the hostname parts.
     */
    static boolean matchHost(String uriPattern, String requestedUri, AntPathMatcher matcher) {
        requestedUri = requestedUri.replace('\\', '/');
        String hostnameFromRequestedUri;
        try {
            URI uri = new URI(requestedUri);
            if (null == uri.getHost()) {
                // If no host and no scheme, then likely relative URI, so just return true
                // If no host but has scheme, then reject (e.g. http://AAA@@attacker.com?.example.com)
                return null == uri.getScheme();
            }
            hostnameFromRequestedUri = uri.getHost();
        }
        catch (URISyntaxException ex) {
            return false;
        }

        StringTokenizer st = new StringTokenizer(uriPattern, "/");
        String hostnameFromPattern = null;
        while (st.hasMoreTokens()) {
            String currentToken = st.nextToken();
            if (currentToken.endsWith(":")) {
                continue;
            }
            hostnameFromPattern = currentToken;
            break;
        }
        if (hostnameFromPattern == null) {
            return false;
        }

        int colonLocation = hostnameFromPattern.indexOf(':');
        if (colonLocation > 0) {
            hostnameFromPattern = hostnameFromPattern.substring(0, colonLocation);
        }

        return matcher.match(hostnameFromPattern, hostnameFromRequestedUri);
    }

    public static String getHostForURI(String uri) {
        if (isUrl(uri)) {
            return UriComponentsBuilder.fromUriString(uri).build().getHost();
        } else {
            //spring-web 5.3 used to throw an IllegalArgumentException if the URL wasn't valid.
            throw new IllegalArgumentException("[" + uri + "] is not a valid HTTP URL");
        }
    }

    public static UriComponentsBuilder fromUriString(String uri) {
        if (!isUrl(uri)) {
            throw new InvalidUrlException(uri + " is not a valid URL");
        }
        return UriComponentsBuilder.fromUriString(uri);
    }

    public static String getBaseURL(HttpServletRequest request) {
        //returns scheme, host and context path
        //for example http://localhost:8080/uaa or http://login.uaa-acceptance.cf-app.com
        String requestURL = request.getRequestURL().toString();
        return hasText(request.getServletPath()) ?
                requestURL.substring(0, requestURL.lastIndexOf(request.getServletPath())) :
                requestURL;
    }

    public static Map<String, String[]> getParameterMap(String uri) {
        UriComponentsBuilder b = UriComponentsBuilder.fromUriString(uri);
        MultiValueMap<String, String> map = b.build().getQueryParams();
        Map<String, String[]> result = new HashMap<>();
        map.forEach((key, value) -> result.put(key, decodeValue(value)));
        return result;
    }

    private static String[] decodeValue(List<String> value) {
        if (value == null) {
            return new String[0];
        }
        String[] result = new String[value.size()];
        int pos = 0;
        for (String s : value) {
            if (s == null) {
                return new String[0];
            }
            result[pos] = UriUtils.decode(s, "UTF-8");
            pos++;
        }
        return result;
    }

    public static boolean isUrl(String url) {
        if (!hasLength(url)) {
            return false;
        }
        try {
            new URL(url).toURI();
            return true;
        } catch (MalformedURLException | URISyntaxException e) {
            return false;
        }
    }

    /**
     * Validates and normalizes a URL for safe use in web contexts to prevent XSS attacks.
     * Only allows:
     * - Context-relative paths starting with /
     * - Absolute HTTP/HTTPS URLs
     * 
     * @param url the URL to validate
     * @param fallbackUrl the fallback URL to use for invalid URLs (should be safe, e.g., "/login")
     * @return the validated URL, or fallbackUrl for invalid URLs
     */
    public static String validateAndNormalizeSafeUrl(String url, String fallbackUrl) {
        if (url == null || url.trim().isEmpty()) {
            return fallbackUrl;
        }
        
        String trimmed = url.trim();
        
        // Allow context-relative paths starting with /
        if (trimmed.startsWith("/")) {
            return trimmed;
        }
        
        // Allow absolute HTTP/HTTPS URLs
        try {
            URI uri = new URI(trimmed);
            String scheme = uri.getScheme();
            if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) {
                return trimmed;
            }
        } catch (URISyntaxException e) {
            // Invalid URI syntax, fall back to default
        }
        
        // For any other scheme (javascript:, data:, etc.) or invalid URLs, fall back to safe default
        return fallbackUrl;
    }

    public static String addQueryParameter(String url, String name, String value) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
        builder.queryParam(name, value);
        return builder.build().toUriString();
    }

    public static String addFragmentComponent(String urlString, String component) {
        URI uri = URI.create(urlString);
        UriComponentsBuilder builder = UriComponentsBuilder.fromUri(uri);
        builder.fragment(hasText(uri.getFragment()) ? (uri.getFragment() + "&" + component) : component);
        return builder.build().toUriString();
    }

    public static String addSubdomainToUrl(String url, String subdomain) {
        if (!hasText(subdomain)) {
            return url;
        }

        subdomain = subdomain.trim();
        subdomain = subdomain.endsWith(".") ? subdomain : (subdomain + ".");

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
        builder.host(subdomain + builder.build().getHost());
        return builder.build().toUriString();
    }

    public static String getSubdomain(String subdomain) {
        if (hasText(subdomain)) {
            subdomain = subdomain.trim();
            subdomain = subdomain.endsWith(".") ? subdomain : (subdomain + ".");
        }
        return subdomain;
    }

    public static String extractPathVariableFromUrl(int pathParameterIndex, String path) {
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        String[] paths = StringUtils.delimitedListToStringArray(path, "/");
        if (paths.length != 0 && pathParameterIndex < paths.length) {
            return paths[pathParameterIndex];
        }
        return null;
    }

    public static String getRequestPath(HttpServletRequest request) {
        String servletPath = request.getServletPath();
        String pathInfo = request.getPathInfo();

        if (servletPath == null) {
            servletPath = UaaStringUtils.EMPTY_STRING;
        }
        if (pathInfo == null) {
            pathInfo = UaaStringUtils.EMPTY_STRING;
        }

        return "%s%s".formatted(servletPath, pathInfo);
    }

    /**
     * Checks if the given request path represents a static resource.
     *
     * @param requestPath the request path to check
     * @return true if the path starts with any of the static resource prefixes
     */
    public static boolean isStaticResource(String requestPath) {
        if (requestPath == null) {
            return false;
        }
        return STATIC_RESOURCE_PREFIXES.stream().anyMatch(requestPath::startsWith);
    }

    /**
     * Checks if the given request represents a static resource by extracting and checking its path.
     *
     * @param request the HTTP servlet request
     * @return true if the request path starts with any of the static resource prefixes
     */
    public static boolean isStaticResource(HttpServletRequest request) {
        return isStaticResource(getRequestPath(request));
    }

    public static boolean uriHasMatchingHost(String uri, String hostname) {
        if (uri == null) {
            return false;
        }

        try {
            URL url = new URL(uri);
            return hostname.equals(url.getHost());
        } catch (MalformedURLException e) {
            return false;
        }
    }

    /* Host and scheme should be case-insensitive, path should be case-sensitive, per RFC 3986 */
    public static String normalizeUri(String uri) {
        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(uri);
        UriComponents nonNormalizedUri = uriComponentsBuilder.build();

        var host = nonNormalizedUri.getHost();
        if (!hasText(host)) {
            throw new IllegalArgumentException("URI host must not be null");
        }
        uriComponentsBuilder.host(host.toLowerCase(Locale.US));

        var schema = nonNormalizedUri.getScheme();
        if (!hasText(schema)) {
            throw new IllegalArgumentException("URI scheme must not be null");
        }
        uriComponentsBuilder.scheme(schema.toLowerCase(Locale.US));
        uriComponentsBuilder.replacePath(decodeUriPath(nonNormalizedUri.getPath()));

        return uriComponentsBuilder.build().toString();
    }

    public static String urlEncode(String inValue) throws IllegalArgumentException {
        String out;
        out = URLEncoder.encode(inValue, UTF_8);
        return out;
    }

    public static Cookie createSavedCookie(String userId, Object value) {
        String cookieValue = ObjectUtils.isEmpty(value) ? UaaStringUtils.EMPTY_STRING : urlEncode(JsonUtils.writeValueAsString(value));
        return new Cookie("Saved-Account-%s".formatted(urlEncode(userId)), cookieValue);
    }

    private static String decodeUriPath(final String path) {
        if (path == null) {
            return null;
        }

        String normalizedPath = path;
        for (int i = 0; i <= MAX_URI_DECODES; ++i) {
            // This loop can run up to (MAX_URI_DECODES + 1) times.
            // The extra iteration is used to check that the URI remains unchanged after decoding.
            String normalizedPathPrev = normalizedPath;
            normalizedPath = StringUtils.uriDecode(normalizedPath, StandardCharsets.UTF_8);
            if (normalizedPath.equals(normalizedPathPrev)) {
                return StringUtils.cleanPath(normalizedPath);
            }
        }

        throw new IllegalArgumentException("Aborted url decoding for repeatedly encoded path");
    }

    /**
     * Normalizes a URL for port comparison by removing standard ports (80 for HTTP, 443 for HTTPS).
     * This ensures that URLs like "http://example.com" and "http://example.com:80" are treated as equivalent.
     *
     * @param url the URL to normalize
     * @return the normalized URL with standard ports removed, or the original URL if malformed
     */
    public static String normalizeUrlForPortComparison(String url) {
        if (url == null) {
            return null;
        }
        try {
            URI uri = new URI(url);
            int port = uri.getPort();
            String scheme = uri.getScheme();

            if (("http".equalsIgnoreCase(scheme) && port == 80) || 
                ("https".equalsIgnoreCase(scheme) && port == 443)) {
                return new URI(scheme, uri.getUserInfo(), uri.getHost(), -1, 
                              uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
            }
        } catch (Exception ignored) {
            // ignore
        }
        return url;
    }
}
