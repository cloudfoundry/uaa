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

import org.apache.directory.api.util.Strings;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.Map;

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
                if (authentication.getCredentials() == null && isGrantAuthorizationCode(authentication.getDetails()) && userDetails instanceof UaaClient) {
                    // in case of grant_type=authorization_code and code_verifier passed (PKCE) we check if client has option allowpublic with true and proceed even if no secret is provided
                    UaaClient uaaClient = (UaaClient) userDetails;
                    Object allowPublic = uaaClient.getAdditionalInformation().get(ClientConstants.ALLOW_PUBLIC);
                    if (allowPublic instanceof String && Boolean.TRUE.toString().equalsIgnoreCase((String)allowPublic) ||
                        allowPublic instanceof Boolean && Boolean.TRUE.equals(allowPublic)) {
                        break;
                    }
                }
                super.additionalAuthenticationChecks(user, authentication);
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

    private boolean isGrantAuthorizationCode(Object uaaAuthenticationDetails) {
        Map<String, String[]> requestParameters = uaaAuthenticationDetails instanceof UaaAuthenticationDetails &&
            ((UaaAuthenticationDetails)uaaAuthenticationDetails).getParameterMap() != null ?
            ((UaaAuthenticationDetails)uaaAuthenticationDetails).getParameterMap() : Collections.emptyMap();
        return PkceValidationService.isCodeVerifierParameterValid(getSafeParameterValue(requestParameters.get("code_verifier"))) &&
            StringUtils.hasText(getSafeParameterValue(requestParameters.get("client_id"))) &&
            StringUtils.hasText(getSafeParameterValue(requestParameters.get("code"))) &&
            StringUtils.hasText(getSafeParameterValue(requestParameters.get("redirect_uri"))) &&
            TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE.equals(getSafeParameterValue(requestParameters.get(ClaimConstants.GRANT_TYPE)));
    }

    private String getSafeParameterValue(String[] value) {
        if (null == value || value.length < 1) {
            return Strings.EMPTY_STRING;
        }
        return StringUtils.hasText(value[0]) ? value[0] : Strings.EMPTY_STRING;
    }
}
