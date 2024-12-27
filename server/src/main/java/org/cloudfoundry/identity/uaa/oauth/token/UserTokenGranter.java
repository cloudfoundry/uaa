/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AbstractTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.USER_TOKEN_REQUESTING_CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;

public class UserTokenGranter extends AbstractTokenGranter {

    private final MultitenantClientServices clientDetailsService;
    private final RevocableTokenProvisioning tokenStore;

    public UserTokenGranter(AuthorizationServerTokenServices tokenServices,
            MultitenantClientServices clientDetailsService,
            OAuth2RequestFactory requestFactory,
            RevocableTokenProvisioning tokenStore) {
        super(tokenServices, clientDetailsService, requestFactory, TokenConstants.GRANT_TYPE_USER_TOKEN);
        this.clientDetailsService = clientDetailsService;
        this.tokenStore = tokenStore;
    }

    @Override
    public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
        //swap the client ID for the recipient
        //so that the rest of the flow continues as normal
        TokenRequest adjusted = new TokenRequest(
                tokenRequest.getRequestParameters(),
                tokenRequest.getRequestParameters().get(USER_TOKEN_REQUESTING_CLIENT_ID),
                tokenRequest.getScope(),
                tokenRequest.getGrantType()
        );
        return super.grant(grantType, adjusted);
    }

    @Override
    protected void validateGrantType(String grantType, ClientDetails clientDetails) {
        //no op. we do all this during validation
    }

    protected Authentication validateRequest(TokenRequest request) {
        //things to validate
        //1. Authentication must exist and be authenticated
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || !(authentication instanceof UaaOauth2Authentication)) {
            throw new InsufficientAuthenticationException("Invalid authentication object:" + authentication);
        }
        UaaOauth2Authentication oauth2Authentication = (UaaOauth2Authentication) authentication;
        //2. authentication must be a user, and authenticated
        if (oauth2Authentication.getUserAuthentication() == null || !oauth2Authentication.getUserAuthentication().isAuthenticated()) {
            throw new InsufficientAuthenticationException("Authentication containing a user is required");
        }
        //3. parameter requesting_client_id must be present
        if (request.getRequestParameters() == null || request.getRequestParameters().get(USER_TOKEN_REQUESTING_CLIENT_ID) == null) {
            throw new InvalidGrantException("Parameter " + USER_TOKEN_REQUESTING_CLIENT_ID + " is required.");
        }
        //4. grant_type must be user_token
        if (!TokenConstants.GRANT_TYPE_USER_TOKEN.equals(request.getGrantType())) {
            throw new InvalidGrantException("Invalid grant type");
        }

        //5. requesting client must have user_token grant type
        ClientDetails requesting = clientDetailsService.loadClientByClientId(request.getRequestParameters().get(USER_TOKEN_REQUESTING_CLIENT_ID), IdentityZoneHolder.get().getId());
        super.validateGrantType(GRANT_TYPE_USER_TOKEN, requesting);

        //6. receiving client must have refresh_token grant type
        ClientDetails receiving = clientDetailsService.loadClientByClientId(request.getRequestParameters().get(CLIENT_ID), IdentityZoneHolder.get().getId());
        super.validateGrantType(GRANT_TYPE_REFRESH_TOKEN, receiving);

        return oauth2Authentication.getUserAuthentication();
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        Authentication userAuth = validateRequest(tokenRequest);
        OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, userAuth);
    }

    protected DefaultOAuth2AccessToken prepareForSerialization(DefaultOAuth2AccessToken token) {
        //get original ID
        String id = token.getValue();
        //nullify the access_token value
        token.setValue(null);
        //ensure that the ID is that of the refresh token
        token.getAdditionalInformation().put(ClaimConstants.JTI, token.getRefreshToken().getValue());
        //delete the access token from token store
        tokenStore.delete(id, 0, IdentityZoneHolder.get().getId());
        return token;
    }

    @Override
    protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
        ClientDetails receivingClient = clientDetailsService.loadClientByClientId(tokenRequest.getRequestParameters().get(CLIENT_ID), IdentityZoneHolder.get().getId());
        return prepareForSerialization((DefaultOAuth2AccessToken) super.getAccessToken(receivingClient, tokenRequest));
    }
}