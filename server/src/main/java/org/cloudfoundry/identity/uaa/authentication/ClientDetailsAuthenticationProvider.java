/*
 * *****************************************************************************
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
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
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
import java.util.Optional;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_EMPTY;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_NONE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_PRIVATE_KEY_JWT;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.getSafeParameterValue;

public class ClientDetailsAuthenticationProvider extends DaoAuthenticationProvider {

    private final JwtClientAuthentication jwtClientAuthentication;

    public ClientDetailsAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder encoder, JwtClientAuthentication jwtClientAuthentication) {
        super();
        setUserDetailsService(userDetailsService);
        setPasswordEncoder(encoder);
        this.jwtClientAuthentication = jwtClientAuthentication;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {


        String[] passwordList;
        String password = userDetails.getPassword();
        if (password != null) {
            passwordList = password.split(" ");
        } else {
            passwordList = new String[]{password};
        }

        AuthenticationException error = null;
        for (String pwd : passwordList) {
            try {
                UaaClient uaaClient = new UaaClient(userDetails, pwd);
                if (ObjectUtils.isEmpty(authentication.getCredentials())) {
                    if (isPublicGrantTypeUsageAllowed(authentication.getDetails()) && uaaClient.isAllowPublic()) {
                        // in case of grant_type=authorization_code and code_verifier passed (PKCE) we check if client has option allowpublic with true and continue even if no secret is in request
                        setAuthenticationMethod(authentication, CLIENT_AUTH_NONE);
                        break;
                    } else if (isPrivateKeyJwt(authentication.getDetails())) {
                        setAuthenticationMethod(authentication, CLIENT_AUTH_PRIVATE_KEY_JWT);
                        if (!validatePrivateKeyJwt(authentication.getDetails(), uaaClient)) {
                            error = new BadCredentialsException("Bad client_assertion type");
                        }
                        break;
                    } else {
                        // set internally empty as client_auth_method e.g. cf client
                        setAuthenticationMethod(authentication, CLIENT_AUTH_EMPTY);
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
        if (error != null) {
            throw error;
        }
    }

    private static void setAuthenticationMethod(AbstractAuthenticationToken authentication, String method) {
        if (authentication.getDetails() instanceof  UaaAuthenticationDetails) {
            ((UaaAuthenticationDetails) authentication.getDetails()).setAuthenticationMethod(method);
        }
    }

    private static boolean isPublicGrantTypeUsageAllowed(Object uaaAuthenticationDetails) {
        UaaAuthenticationDetails authenticationDetails = getUaaAuthenticationDetails(uaaAuthenticationDetails);
        Map<String, String[]> requestParameters = getRequestParameters(authenticationDetails);
        return isPublicTokenRequest(authenticationDetails) && (isAuthorizationWithPkce(requestParameters) || isRefreshFlow(requestParameters));
    }

    private static boolean isPublicTokenRequest(UaaAuthenticationDetails authenticationDetails) {
        return !authenticationDetails.isAuthorizationSet() && "/oauth/token".equals(authenticationDetails.getRequestPath());
    }

    private static boolean isAuthorizationWithPkce(Map<String, String[]> requestParameters) {
        return PkceValidationService.isCodeVerifierParameterValid(getSafeParameterValue(requestParameters.get("code_verifier"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_id"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("code"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("redirect_uri"))) &&
                TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE.equals(getSafeParameterValue(requestParameters.get(ClaimConstants.GRANT_TYPE)));
    }

    private static boolean isRefreshFlow(Map<String, String[]> requestParameters) {
        return StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_id")))
                && StringUtils.hasText(getSafeParameterValue(requestParameters.get("refresh_token")))
                && TokenConstants.GRANT_TYPE_REFRESH_TOKEN.equals(getSafeParameterValue(requestParameters.get(ClaimConstants.GRANT_TYPE)));
    }

    private static UaaAuthenticationDetails getUaaAuthenticationDetails(Object object) {
        return object instanceof UaaAuthenticationDetails uad ? uad : new UaaAuthenticationDetails();
    }

    private static Map<String, String[]> getRequestParameters(UaaAuthenticationDetails authenticationDetails) {
        return Optional.ofNullable(authenticationDetails.getParameterMap()).orElse(Collections.emptyMap());
    }

    private static boolean isPrivateKeyJwt(Object uaaAuthenticationDetails) {
        UaaAuthenticationDetails authenticationDetails = getUaaAuthenticationDetails(uaaAuthenticationDetails);
        Map<String, String[]> requestParameters = getRequestParameters(authenticationDetails);
        return isPublicTokenRequest(authenticationDetails) &&
                !StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_secret"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_assertion_type"))) &&
                StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_assertion")));
    }

    private boolean validatePrivateKeyJwt(Object uaaAuthenticationDetails, UaaClient uaaClient) {
        return jwtClientAuthentication.validateClientJwt(getRequestParameters(getUaaAuthenticationDetails(uaaAuthenticationDetails)),
                uaaClient.getClientJwtConfiguration(), uaaClient.getUsername());
    }
}
