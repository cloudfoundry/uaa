package org.cloudfoundry.identity.uaa.oauth.beans;

import lombok.SneakyThrows;
import org.apache.commons.lang.ArrayUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap.SimpleEntry;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;
import static org.springframework.util.StringUtils.isEmpty;

public class LegacyRedirectResolver extends org.cloudfoundry.identity.uaa.oauth.beans.org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver {
    private static final Logger logger = LoggerFactory.getLogger(LegacyRedirectResolver.class);
    static final String MSG_TEMPLATE = "OAuth client %s is configured with a redirect_uri which performs implicit or " +
            "wildcard matching in legacy redirect uri matching mode. In this instance, the requested uri %s matches the " +
            "configured uri %s. Please consider configuring your requested redirect uri to exactly match the " +
            "redirect_uri for this client.";

    private final SpecCompliantRedirectMatcher specCompliantRedirectMatcher = new SpecCompliantRedirectMatcher();

    @Override
    protected boolean redirectMatches(String requestedRedirect, String clientRedirect) {
        try {
            ClientRedirectUriPattern clientRedirectUri = new ClientRedirectUriPattern(clientRedirect);

            if (!clientRedirectUri.isValidRedirect()) {
                logger.error(String.format("Invalid redirect uri: %s", clientRedirect));
                return false;
            }
            Predicate<String> matcher;
            if (isWildcard(clientRedirect)) {
                matcher = req -> clientRedirectUri.isSafeRedirect(req) && clientRedirectUri.match(req);
            } else {
                matcher = req -> super.redirectMatches(req, clientRedirect);
            }
            return matches(matcher, requestedRedirect);
        } catch (IllegalArgumentException e) {
            logger.error(
                    String.format("Could not validate whether requestedRedirect (%s) matches clientRedirectUri (%s)",
                            requestedRedirect,
                            clientRedirect),
                    e);
            return false;
        }
    }

    /**
     * Repeatedly:
     * <ol>
     *     <li>checks for a match</li>
     *     <li>url decodes the requested path</li>
     * </ol>
     * until path cannot be url decoded any further. Then normalizes the path before the final check.
     * <p>
     *     For example, if example.com/foo is the registered url and example.com/foo/%252e./bar is the requested url,
     *     checks a match for:
     *     <ol>
     *         <li>example.com/foo/%252e./bar</li>
     *         <li>example.com/foo/%2e./bar</li>
     *         <li>example.com/foo/../bar</li>
     *         <li>example.com/bar</li>
     *     </ol>
     * </p>
     */
    private boolean matches(Predicate<String> matcher, String requestedRedirect) {
        int maxDecodeAttempts = 5;
        for (int i = 1; i <= maxDecodeAttempts; i++) {
            if (!matcher.test(requestedRedirect)) {
                return false;
            }
            String decoded = urlDecode(requestedRedirect);
            if (decoded.equals(requestedRedirect)) {
                return matcher.test(StringUtils.cleanPath(decoded));
            }
            requestedRedirect = decoded;
        }
        logger.debug("Aborted url decoding loop to mitigate DOS attack that sends a repeatedly url-encoded path");
        return false;
    }

    @SneakyThrows
    private String urlDecode(String url) {
        return URLDecoder.decode(url, StandardCharsets.UTF_8.name());
    }

    @Override
    public String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception {
        Set<String> registeredRedirectUris = ofNullable(client.getRegisteredRedirectUri()).orElse(emptySet());

        if (registeredRedirectUris.isEmpty()) {
            throw new RedirectMismatchException("Client registration is missing redirect_uri");
        }

        List<String> invalidUrls = registeredRedirectUris.stream()
                .filter(url -> !UaaUrlUtils.isValidRegisteredRedirectUrl(url))
                .collect(toList());

        if (!invalidUrls.isEmpty()) {
            throw new RedirectMismatchException("Client registration contains invalid redirect_uri: " + invalidUrls);
        }

        String resolveRedirect = super.resolveRedirect(requestedRedirect, client);

        // This legacy resolver decided that the requested redirect URI was a match for one
        // of the configured redirect uris (i.e. super.resolveRedirect() did not throw), so
        // check to see if we need to log some warnings before returning.
        logConfiguredRedirectUrisWhichOnlyMatchFuzzily(client.getClientId(), registeredRedirectUris, requestedRedirect);

        return resolveRedirect;
    }

    private void logConfiguredRedirectUrisWhichOnlyMatchFuzzily(String clientId, Set<String> registeredRedirectUris, String requestedRedirect) {
        // For each registered redirect uri considered to be a match by this class, log a warning
        // when the standard Spring library class disagrees (i.e. when it acts more strictly).
        registeredRedirectUris.stream()
                .filter(registeredRedirectUri ->
                        requestedRedirect != null &&
                                this.redirectMatches(requestedRedirect, registeredRedirectUri) &&
                                !specCompliantRedirectMatcher.redirectMatches(requestedRedirect, registeredRedirectUri)
                )
                .forEach(registeredRedirectUri ->
                        logger.warn(String.format(MSG_TEMPLATE, clientId,
                                redactSensitiveInformation(requestedRedirect), registeredRedirectUri)
                        )
                );
    }

    private static String redactSensitiveInformation(String uri) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri);
        redactQueryParams(builder);
        redactUserInfo(builder);
        redactHashFragment(builder);
        return builder.toUriString();
    }

    private static void redactQueryParams(UriComponentsBuilder builder) {
        MultiValueMap<String, String> originalParams = builder.build().getQueryParams();
        Map<String, List<String>> redactedParams = originalParams.entrySet()
                .stream()
                .map(e -> new SimpleEntry<>(e.getKey(), e.getValue().stream().map(v -> "REDACTED").collect(toList())))
                .collect(toMap(Map.Entry::getKey, Map.Entry::getValue));

        builder.queryParams(new LinkedMultiValueMap<>(redactedParams));
    }

    private static void redactUserInfo(UriComponentsBuilder builder) {
        String userInfo = builder.build().getUserInfo();
        if (!isEmpty(userInfo)) {
            builder.userInfo("REDACTED:REDACTED");
        }
    }

    private static void redactHashFragment(UriComponentsBuilder builder) {
        if (!isEmpty(builder.build().getFragment())) {
            builder.fragment("REDACTED");
        }
    }

    private static boolean isWildcard(String configuredRedirectPattern) {
        return configuredRedirectPattern.contains("*");
    }


    private class SpecCompliantRedirectMatcher {
        private final CurrentVersionOfSpringResolverWithMethodExposedAndSubdomainsOff matcher =
                new CurrentVersionOfSpringResolverWithMethodExposedAndSubdomainsOff();

        boolean redirectMatches(String requestedRedirect, String redirectUri) {
            return matcher.redirectMatches(requestedRedirect, redirectUri);
        }

        private class CurrentVersionOfSpringResolverWithMethodExposedAndSubdomainsOff extends org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver {
            CurrentVersionOfSpringResolverWithMethodExposedAndSubdomainsOff() {
                super();
                setMatchSubdomains(false);
            }

            public boolean redirectMatches(String requestedRedirect, String redirectUri) {
                return super.redirectMatches(requestedRedirect, redirectUri);
            }
        }
    }

    private static class ClientRedirectUriPattern {
        // The URI spec provides a regex for matching URI parts
        // https://tools.ietf.org/html/rfc3986#appendix-B
        private static final Pattern URI_EXTRACTOR =
                Pattern.compile("^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?");

        private static final int URI_EXTRACTOR_AUTHORITY_GROUP = 4; // "Authority" means "user:password@example.com"

        private Matcher redirectMatcher;
        private boolean isValidRedirect = true;
        private AntPathMatcher matcher;
        private String redirectUri;

        ClientRedirectUriPattern(String redirectUri) {
            if (redirectUri == null) {
                throw new IllegalArgumentException("Client Redirect URI was null");
            }

            this.redirectUri = redirectUri;
            matcher = new AntPathMatcher();
            this.redirectMatcher = URI_EXTRACTOR.matcher(redirectUri);
            if (!redirectMatcher.matches()) {
                isValidRedirect = false;
            }
        }

        boolean isSafeRedirect(String requestedRedirect) {
            // We iterate backwards through the hosts to make sure the TLD and domain match
            String[] configuredRedirectHost = splitAndReverseHost(getHost());
            String[] requestedRedirectHost = splitAndReverseHost(URI.create(requestedRedirect).getHost());

            if (requestedRedirectHost.length < configuredRedirectHost.length) {
                return false;
            }

            boolean isSafe = true;
            for (int i = 0; i < configuredRedirectHost.length && !isWildcard(configuredRedirectHost[i]); i++) {
                isSafe = isSafe && configuredRedirectHost[i].equals(requestedRedirectHost[i]);
            }

            return isSafe;
        }

        boolean isValidRedirect() {
            return isValidRedirect;
        }

        boolean match(String requestedRedirect) {
            return matcher.match(redirectUri, requestedRedirect);
        }

        private String getHost() {
            String authority = redirectMatcher.group(URI_EXTRACTOR_AUTHORITY_GROUP);
            return stripPort(stripAuthority(authority));
        }

        private String stripAuthority(String authority) {
            if (authority.contains("@")) {
                return authority.split("@")[1];
            }
            return authority;
        }

        private String stripPort(String hostAndPort) {
            if (hostAndPort.contains(":")) {
                return hostAndPort.split(":")[0];
            }
            return hostAndPort;
        }

        private static String[] splitAndReverseHost(String host) {
            String[] parts = host.split("\\.");
            ArrayUtils.reverse(parts);
            return parts;
        }
    }
}
