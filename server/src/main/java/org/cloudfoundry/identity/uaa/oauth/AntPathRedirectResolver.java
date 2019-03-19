/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.lang.ArrayUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;
import org.springframework.util.AntPathMatcher;

import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;

public class AntPathRedirectResolver extends DefaultRedirectResolver {
    private static final Logger logger = LoggerFactory.getLogger(AntPathRedirectResolver.class);

    @Override
    protected boolean redirectMatches(String requestedRedirect, String clientRedirect) {
        try {
            URI requestedRedirectURI = URI.create(requestedRedirect);
            ClientRedirectUriPattern clientRedirectUri = new ClientRedirectUriPattern(clientRedirect);

            if (!clientRedirectUri.isValidRedirect()) {
                logger.error(String.format("Invalid redirect uri: %s", clientRedirect));
                return false;
            }

            if (clientRedirectUri.isWildcard(clientRedirect) &&
                    clientRedirectUri.isSafeRedirect(requestedRedirectURI) &&
                    clientRedirectUri.match(requestedRedirectURI)) {
                return true;
            }

            return super.redirectMatches(requestedRedirect, clientRedirect);
        } catch (IllegalArgumentException e) {
            logger.error(
                    String.format("Could not validate whether requestedRedirect (%s) matches clientRedirectUri (%s)",
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
                .collect(Collectors.toList());

        if (!invalidUrls.isEmpty()) {
            throw new RedirectMismatchException("Client registration contains invalid redirect_uri: " + invalidUrls);
        }

        return super.resolveRedirect(requestedRedirect, client);
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

        boolean isSafeRedirect(URI requestedRedirect) {
            // We iterate backwards through the hosts to make sure the TLD and domain match
            String[] configuredRedirectHost = splitAndReverseHost(getHost());
            String[] requestedRedirectHost = splitAndReverseHost(requestedRedirect.getHost());

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
            return matcher.match(redirectUri, requestedRedirect.toString());
        }

        private boolean isWildcard(String configuredRedirectPattern) {
            return configuredRedirectPattern.contains("*");
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
