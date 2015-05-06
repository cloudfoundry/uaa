/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

//TODO - make object serialize/deserialize properly with JSON
public class PasscodeInformation {

    private String userId;
    private String username;
    private String passcode;
    private Map<String, Object> authorizationParameters;
    private String origin;

    public PasscodeInformation(
        String userId,
        String username,
        String passcode,
        String origin,
        Map<String, Object> authorizationParameters) {

        setUserId(userId);
        setUsername(username);
        setPasscode(passcode);
        setAuthorizationParameters(authorizationParameters);
        setOrigin(origin);
    }

    @JsonCreator
    public PasscodeInformation(
        @JsonProperty("userId") String userId,
        @JsonProperty("username") String username,
        @JsonProperty("passcode") String passcode,
        @JsonProperty("origin") String origin,
        @JsonProperty("samlAuthorities") ArrayList<SamlUserAuthority> authorities) {

        setUserId(userId);
        setUsername(username);
        setPasscode(passcode);
        authorizationParameters = new LinkedHashMap<String, Object>();
        setSamlAuthorities(authorities);
        setOrigin(origin);
    }

    public PasscodeInformation(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @JsonProperty("samlAuthorities")
    public ArrayList<SamlUserAuthority> getSamlAuthorities() {
        ArrayList<SamlUserAuthority> list = new ArrayList<SamlUserAuthority>();
        if (authorizationParameters != null && authorizationParameters.containsKey("authorities")) {
            Set<SamlUserAuthority> set = (Set<SamlUserAuthority>) authorizationParameters.get("authorities");
            list.addAll(set);
        }
        return list;
    }

    public void setSamlAuthorities(ArrayList<SamlUserAuthority> authorities) {
        Set<SamlUserAuthority> set = new HashSet<SamlUserAuthority>();
        set.addAll(authorities);
        authorizationParameters.put("authorities", set);
    }

    @JsonIgnore
    public Map<String, Object> getAuthorizationParameters() {
        return authorizationParameters;
    }

    public void setAuthorizationParameters(Map<String, Object> authorizationParameters) {
        this.authorizationParameters = authorizationParameters;
    }

    public String getPasscode() {
        return passcode;
    }

    public void setPasscode(String passcode) {
        this.passcode = passcode;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
