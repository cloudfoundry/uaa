/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
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


import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.util.Assert;

public class HybridTokenGranterForAuthorizationCode extends AbstractTokenGranter {
    private static final String GRANT_TYPE = "authorization_code";

    public HybridTokenGranterForAuthorizationCode(AuthorizationServerTokenServices tokenServices,
                                                  ClientServicesExtension clientDetailsService,
                                                  OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest clientToken) {

        Authentication userAuth = SecurityContextHolder.getContext().getAuthentication();
        if (userAuth==null || !userAuth.isAuthenticated()) {
            throw new InsufficientAuthenticationException("There is no currently logged in user");
        }
        Assert.state(clientToken instanceof ImplicitTokenRequest, "An ImplicitTokenRequest is required here. Caller needs to wrap the TokenRequest.");

        OAuth2Request requestForStorage = ((ImplicitTokenRequest)clientToken).getOAuth2Request();

        return new OAuth2Authentication(requestForStorage, userAuth);

    }
}
