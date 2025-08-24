/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.passcode;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.provider.saml.SamlUserAuthority;
import org.springframework.security.core.Authentication;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Data
public class PasscodeInformation {

    private static final String AUTHORITIES_KEY = "authorities";
    private String userId;
    private String username;
    private String passcode;
    @JsonIgnore
    private Map<String, Object> authorizationParameters;
    private String origin;

    @JsonCreator
    public PasscodeInformation(
            @JsonProperty("userId") String userId,
            @JsonProperty("username") String username,
            @JsonProperty("passcode") String passcode,
            @JsonProperty("origin") String origin,
            @JsonProperty("samlAuthorities") List<SamlUserAuthority> authorities) {

        setUserId(userId);
        setUsername(username);
        setPasscode(passcode);
        authorizationParameters = new LinkedHashMap<>();
        setSamlAuthorities(authorities);
        setOrigin(origin);
    }

    public PasscodeInformation(Principal principal, Map<String, Object> authorizationParameters) {
        UaaPrincipal uaaPrincipal;
        if (principal instanceof UaaPrincipal castUaaPrincipal) {
            uaaPrincipal = getUaaPrincipal(castUaaPrincipal);
        } else if (principal instanceof UaaAuthentication castUaaAuthentication) {
            uaaPrincipal = getUaaPrincipal(castUaaAuthentication.getPrincipal());
        } else if (
                principal instanceof Authentication castAuthentication &&
                        castAuthentication.getPrincipal() instanceof UaaPrincipal castUaaPrincipal
        ) {
            uaaPrincipal = getUaaPrincipal(castUaaPrincipal);
        } else {
            throw new PasscodeEndpoint.UnknownPrincipalException();
        }
        setOrigin(uaaPrincipal.getOrigin());
        setUserId(uaaPrincipal.getId());

        setPasscode(null);
        setAuthorizationParameters(authorizationParameters);
    }

    private UaaPrincipal getUaaPrincipal(UaaPrincipal castUaaPrincipal) {
        setUsername(castUaaPrincipal.getName());
        return castUaaPrincipal;
    }

    @JsonProperty("samlAuthorities")
    public List<SamlUserAuthority> getSamlAuthorities() {
        ArrayList<SamlUserAuthority> list = new ArrayList<>();
        if (authorizationParameters != null && authorizationParameters.containsKey(AUTHORITIES_KEY)) {
            Set<SamlUserAuthority> set = (Set<SamlUserAuthority>) authorizationParameters.get(AUTHORITIES_KEY);
            list.addAll(set);
        }
        return list;
    }

    public void setSamlAuthorities(List<SamlUserAuthority> authorities) {
        Set<SamlUserAuthority> set = new HashSet<>(authorities);
        authorizationParameters.put(AUTHORITIES_KEY, set);
    }
}
