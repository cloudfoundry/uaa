/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml.SamlAuthentication;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;

public class LoginSamlAuthenticationToken {

    public static final String AUTHENTICATION_CONTEXT_CLASS_REFERENCE = "acr";

    private final UaaPrincipal uaaPrincipal;
    private SamlAuthentication token;
    private TimeService time = new TimeServiceImpl();

    public LoginSamlAuthenticationToken(UaaPrincipal uaaPrincipal, SamlAuthentication token) {
        this.uaaPrincipal = uaaPrincipal;
        this.token = token;
    }

    public LoginSamlAuthenticationToken setTime(TimeService time) {
        this.time = time;
        return this;
    }

    public UaaPrincipal getUaaPrincipal() {
        return uaaPrincipal;
    }

    public UaaAuthentication getUaaAuthentication(List<? extends GrantedAuthority> uaaAuthorityList,
                                                  Set<String> externalGroups,
                                                  MultiValueMap<String, String> userAttributes,
                                                  long sessionExpiration) {
        LinkedMultiValueMap<String, String> customAttributes = new LinkedMultiValueMap<>();
        for (Map.Entry<String, List<String>> entry : userAttributes.entrySet()) {
            if (entry.getKey().startsWith(USER_ATTRIBUTE_PREFIX)) {
                customAttributes.put(entry.getKey().substring(USER_ATTRIBUTE_PREFIX.length()), entry.getValue());
            }
        }
        UaaAuthentication authentication =
            new UaaAuthentication(
                getUaaPrincipal(),
                token,
                uaaAuthorityList,
                externalGroups,
                customAttributes,
                null,
                true,
                time.getCurrentTimeMillis(),
                sessionExpiration);
        authentication.setAuthenticationMethods(Collections.singleton("ext"));
        List<String> acrValues = userAttributes.get(AUTHENTICATION_CONTEXT_CLASS_REFERENCE);
        if (acrValues !=null) {
            authentication.setAuthContextClassRef(new HashSet<>(acrValues));
        }
        return authentication;
    }
}
