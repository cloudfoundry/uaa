package org.cloudfoundry.identity.uaa.oauth.beans;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.AbstractMap.SimpleEntry;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toMap;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.normalizeUri;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.isEmpty;

public class LegacyRedirectResolver extends org.cloudfoundry.identity.uaa.oauth.beans.org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver {
    private static final Logger logger = LoggerFactory.getLogger(LegacyRedirectResolver.class);

    public static final String LEGACY_PORT_WILDCAR = ":*";

    static final String MSG_TEMPLATE = "OAuth client %s is configured with a redirect_uri which performs implicit or " +
            "wildcard matching in legacy redirect uri matching mode. In this instance, the requested uri %s matches the " +
            "configured uri %s. Please consider configuring your requested redirect uri to exactly match the " +
            "redirect_uri for this client.";

    private final SpecCompliantRedirectMatcher specCompliantRedirectMatcher = new SpecCompliantRedirectMatcher();

    @Override
    protected boolean redirectMatches(String requestedRedirect, String clientRedirect) {
        try {
            String normalizedRequestedRedirect = normalizeUri(requestedRedirect);
            String normalizedClientRedirect = normalizeWildcardUri(clientRedirect);

            URI requestedRedirectURI = URI.create(normalizedRequestedRedirect);
            ClientRedirectUriPattern clientRedirectUri = new ClientRedirectUriPattern(normalizedClientRedirect);

            if (!clientRedirectUri.isValidRedirect()) {
                logger.error("Invalid redirect uri: %s".formatted(normalizedClientRedirect));
                return false;
            }

            if (clientRedirectUri.isWildcard(normalizedClientRedirect) &&
                    clientRedirectUri.isSafeRedirect(requestedRedirectURI) &&
                    clientRedirectUri.match(requestedRedirectURI)) {
                return true;
            }

            return super.redirectMatches(normalizedRequestedRedirect, normalizedClientRedirect);
        } catch (IllegalArgumentException e) {
            logger.error(
                    "Could not validate whether requestedRedirect (%s) matches clientRedirectUri (%s)".formatted(
                            requestedRedirect,
                            clientRedirect),
                    e);
            return false;
        }
    }

    @Override
    public String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception {
        Set<String> registeredRedirectUris = ofNullable(client.getRegisteredRedirectUri()).orElse(emptySet());

        if (registeredRedirectUris.isEmpty()) {
            throw new RedirectMismatchException("Client registration is missing redirect_uri");
        }

        List<String> invalidUrls = registeredRedirectUris.stream()
                .filter(url -> !UaaUrlUtils.isValidRegisteredRedirectUrl(url))
                .toList();

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
                        registeredRedirectUri.contains(LEGACY_PORT_WILDCAR) ||
                                (requestedRedirect != null &&
                                        this.redirectMatches(requestedRedirect, registeredRedirectUri) &&
                                        !specCompliantRedirectMatcher.redirectMatches(requestedRedirect, registeredRedirectUri))
                )
                .forEach(registeredRedirectUri ->
                        logger.warn(MSG_TEMPLATE.formatted(clientId,
                                redactSensitiveInformation(requestedRedirect), registeredRedirectUri)
                        )
                );
    }

    private static String normalizeWildcardUri(String uriClient) {
        boolean hasWildcarPort = uriClient.contains(LEGACY_PORT_WILDCAR);
        String uri = hasWildcarPort ? uriClient.replace(LEGACY_PORT_WILDCAR, StringUtils.EMPTY) : uriClient;
        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(uri);
        UriComponents nonNormalizedUri = uriComponentsBuilder.build();

        try {
            if (nonNormalizedUri.getHost() != null) {
                uriComponentsBuilder.host(nonNormalizedUri.getHost().toLowerCase());
            }
            if (nonNormalizedUri.getScheme() != null) {
                uriComponentsBuilder.scheme(nonNormalizedUri.getScheme().toLowerCase());
            }
            if (hasWildcarPort) {
                uriComponentsBuilder.port(99999);
            }
        } catch (NullPointerException e) {
            throw new IllegalArgumentException("URI host and scheme must not be null");
        }

        return uriComponentsBuilder.build().toString().replace(":99999", LEGACY_PORT_WILDCAR);
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
                .map(e -> new SimpleEntry<>(e.getKey(), e.getValue().stream().map(v -> "REDACTED").toList()))
                .collect(toMap(Map.Entry::getKey, Map.Entry::getValue));

        builder.replaceQueryParams(new LinkedMultiValueMap<>(redactedParams));
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

    private class SpecCompliantRedirectMatcher {
        private final CurrentVersionOfSpringResolverWithMethodExposedAndSubdomainsOff matcher =
                new CurrentVersionOfSpringResolverWithMethodExposedAndSubdomainsOff();

        boolean redirectMatches(String requestedRedirect, String redirectUri) {
            return matcher.redirectMatches(requestedRedirect, redirectUri);
        }

        private class CurrentVersionOfSpringResolverWithMethodExposedAndSubdomainsOff extends org.cloudfoundry.identity.uaa.oauth.provider.endpoint.DefaultRedirectResolver {
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
        private static final String WILDCARD_PORT = "99999";
        private static final String WILDCARD_PORT_PATTERN = ":" + WILDCARD_PORT;

        private Matcher redirectMatcher;
        private boolean isValidRedirect = true;
        private boolean hasWildcardPort;
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
            this.hasWildcardPort = isWildcardPort(redirectUri);
        }

        boolean isSafeRedirect(URI requestedRedirect) {
            // We iterate backwards through the hosts to make sure the TLD and domain match
            String[] configuredRedirectHost = splitAndReverseHost(getHost());
            String[] requestedRedirectHost = splitAndReverseHost((Optional.ofNullable(requestedRedirect.getHost()).orElse("")));

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

        boolean match(URI requestedRedirect) {
            if (hasWildcardPort) {
                if (requestedRedirect.getPort() > 0) {
                    return matcher.match(redirectUri, requestedRedirect.toString().replace(String.valueOf(requestedRedirect.getPort()), WILDCARD_PORT));
                } else {
                    return matcher.match(redirectUri.replace(WILDCARD_PORT_PATTERN, StringUtils.EMPTY), requestedRedirect.toString());
                }
            }
            return matcher.match(redirectUri, requestedRedirect.toString());
        }

        private boolean isWildcard(String configuredRedirectPattern) {
            return configuredRedirectPattern.contains("*") || hasWildcardPort;
        }

        private boolean isWildcardPort(String configuredRedirectPattern) {
            return configuredRedirectPattern.contains(WILDCARD_PORT_PATTERN);
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
