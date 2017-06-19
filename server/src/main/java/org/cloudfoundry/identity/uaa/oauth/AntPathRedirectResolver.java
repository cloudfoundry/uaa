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

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;
import org.springframework.util.AntPathMatcher;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;

public class AntPathRedirectResolver extends DefaultRedirectResolver {


    @Override
    protected boolean redirectMatches(String requestedRedirect, String redirectUri) {
        AntPathMatcher matcher = new AntPathMatcher("/");
        if (redirectUri!=null &&
            redirectUri.contains("*") &&
            matcher.match(redirectUri, requestedRedirect)) {
            return true;
        } else {
            return super.redirectMatches(requestedRedirect, redirectUri);
        }
    }

    @Override
    public String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception {
        Set<String> registeredRedirectUris = ofNullable(client.getRegisteredRedirectUri()).orElse(emptySet());
        if (registeredRedirectUris.size()==0) {
            throw new RedirectMismatchException("Client registration is missing redirect_uri");
        }
        List<String> invalidUrls = registeredRedirectUris.stream().filter(url -> !UaaUrlUtils.isValidRegisteredRedirectUrl(url)).collect(Collectors.toList());
        if (invalidUrls.size()>0) {
                throw new RedirectMismatchException("Client registration contains invalid redirect_uri: " + invalidUrls);
        }
        return super.resolveRedirect(requestedRedirect, client);
    }
}
