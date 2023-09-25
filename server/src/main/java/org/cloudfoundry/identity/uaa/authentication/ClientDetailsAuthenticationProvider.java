/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_NONE;

public class ClientDetailsAuthenticationProvider extends DaoAuthenticationProvider {


    public ClientDetailsAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder encoder) {
        super();
        setUserDetailsService(userDetailsService);
        setPasswordEncoder(encoder);
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {


        String[] passwordList;
        String password = userDetails.getPassword();
        if(password != null) {
            passwordList = password.split(" ");
        } else {
            passwordList = new String[] {password};
        }

        AuthenticationException error = null;
        for(String pwd: passwordList) {
            try {
                User user = new User(userDetails.getUsername(), pwd, userDetails.isEnabled(), userDetails.isAccountNonExpired(), userDetails.isCredentialsNonExpired(), userDetails.isAccountNonLocked(), userDetails.getAuthorities());
                if (userDetails instanceof UaaClient) {
                    UaaClient uaaClient = (UaaClient) userDetails;
                    if (authentication.getCredentials() == null && isPublicGrantTypeUsageAllowed(authentication.getDetails())) {
                        // in case of grant_type=authorization_code and code_verifier passed (PKCE) we check if client has option allowpublic with true and proceed even if no secret is provided
                        Object allowPublic = uaaClient.getAdditionalInformation().get(ClientConstants.ALLOW_PUBLIC);
                        if ((allowPublic instanceof String && Boolean.TRUE.toString().equalsIgnoreCase((String) allowPublic)) ||
                            (allowPublic instanceof Boolean && Boolean.TRUE.equals(allowPublic))) {
                            setAuthenticationMethodNone(authentication);
                            break;
                        }
                    } else if (ObjectUtils.isEmpty(authentication.getCredentials()) && IdentityZoneHolder.get().getConfig().getClientSecretPolicy().getMinLength() == 0) {
                        // set none as client_auth_method for all usage of empty secrets, e.g. cf client
                        setAuthenticationMethodNone(authentication);
                    }
                }
                if (uaaClient.getPassword() == null) {
                    error = new BadCredentialsException("Missing credentials");
                    break;
                }
                super.additionalAuthenticationChecks(uaaClient, authentication);
                error = null;
                break;
            } catch (AuthenticationException e) {
                error = e;
            }
        }
        if (error!=null) {
            throw error;
        }
    }

    private static void setAuthenticationMethodNone(AbstractAuthenticationToken authentication) {
        if (authentication.getDetails() instanceof  UaaAuthenticationDetails) {
            ((UaaAuthenticationDetails) authentication.getDetails()).setAuthenticationMethod(CLIENT_AUTH_NONE);
        }
    }

    private boolean isPublicGrantTypeUsageAllowed(Object uaaAuthenticationDetails) {
        UaaAuthenticationDetails authenticationDetails = uaaAuthenticationDetails instanceof UaaAuthenticationDetails ?
            (UaaAuthenticationDetails)  uaaAuthenticationDetails : new UaaAuthenticationDetails();
        Map<String, String[]> requestParameters = authenticationDetails.getParameterMap() != null ?
            authenticationDetails.getParameterMap() : Collections.emptyMap();
        return isPublicTokenRequest(authenticationDetails) && (isAuthorizationWithPkce(requestParameters) || isRefreshFlow(requestParameters));
    }

    private static boolean isPublicTokenRequest(UaaAuthenticationDetails authenticationDetails) {
        return !authenticationDetails.isAuthorizationSet() && "/oauth/token".equals(authenticationDetails.getRequestPath());
    }

    private boolean isAuthorizationWithPkce(Map<String, String[]> requestParameters) {
        return PkceValidationService.isCodeVerifierParameterValid(getSafeParameterValue(requestParameters.get("code_verifier"))) &&
            StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_id"))) &&
            StringUtils.hasText(getSafeParameterValue(requestParameters.get("code"))) &&
            StringUtils.hasText(getSafeParameterValue(requestParameters.get("redirect_uri"))) &&
            TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE.equals(getSafeParameterValue(requestParameters.get(ClaimConstants.GRANT_TYPE)));
    }

    private boolean isRefreshFlow(Map<String, String[]> requestParameters) {
        return StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_id")))
            && StringUtils.hasText(getSafeParameterValue(requestParameters.get("refresh_token")))
            && TokenConstants.GRANT_TYPE_REFRESH_TOKEN.equals(getSafeParameterValue(requestParameters.get(ClaimConstants.GRANT_TYPE)));
    }

    private String getSafeParameterValue(String[] value) {
        if (null == value || value.length < 1) {
            return UaaStringUtils.EMPTY_STRING;
        }
        return StringUtils.hasText(value[0]) ? value[0] : UaaStringUtils.EMPTY_STRING;
    }
}
