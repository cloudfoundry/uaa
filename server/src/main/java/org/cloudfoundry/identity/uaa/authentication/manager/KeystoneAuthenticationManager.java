/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication.manager;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import java.util.Arrays;
import java.util.Map;

public class KeystoneAuthenticationManager extends RestAuthenticationManager {

    public KeystoneAuthenticationManager() {
    }

    @Override
    protected HttpHeaders getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        return headers;
    }

    @Override
    protected boolean evaluateResponse(Authentication authentication, ResponseEntity<Map> response) {
        boolean v2 = true;
        Map<String, Object> map = (Map<String, Object>)response.getBody().get("access");
        if (map==null) {
            v2 = false;
            map = (Map<String, Object>)response.getBody().get("token");
        }
        Map<String, Object> user = (Map<String, Object>)map.get("user");
        return (authentication.getPrincipal().toString().equals(user.get(v2?"username":"name")));
    }

    @Override
    protected KeystoneAuthenticationRequest getParameters(String username, String password) {
        if (getRemoteUrl()!=null && getRemoteUrl().indexOf("/v2.0")>0) {
            return new KeystoneV2AuthenticationRequest("", username, password);
        } else if (getRemoteUrl()!=null && getRemoteUrl().indexOf("/v3")>0) {
            return new KeystoneV3AuthenticationRequest("", username, password);
        } else {
            throw new UnsupportedOperationException("Unable to determine API version:"+ getRemoteUrl());
        }

    }


    public static interface KeystoneAuthenticationRequest {
    }

    public static class KeystoneV2AuthenticationRequest implements KeystoneAuthenticationRequest{
        private KeystoneAuthentication auth;

        public KeystoneV2AuthenticationRequest(String tenant, String username, String password) {
            auth = new KeystoneAuthentication(tenant, username, password);
        }

        public KeystoneV2AuthenticationRequest(KeystoneAuthentication auth) {
            this.auth = auth;
        }

        @JsonProperty("auth")
        public KeystoneAuthentication getAuth() {
            return auth;
        }

        @JsonProperty("auth")
        public void setAuth(KeystoneAuthentication auth) {
            this.auth = auth;
        }


        public static class KeystoneAuthentication {
            private String tenant;
            private KeystoneCredentials credentials;

            public KeystoneAuthentication(String tenant, String username, String password) {
                this.tenant = tenant;
                this.credentials = new KeystoneCredentials(username, password);
            }

            @JsonProperty("tenantName")
            public String getTenant() {
                return tenant;
            }

            @JsonProperty("tenantName")
            public void setTenant(String tenant) {
                this.tenant = tenant;
            }

            @JsonProperty("passwordCredentials")
            public KeystoneCredentials getCredentials() {
                return credentials;
            }

            public void setCredentials(KeystoneCredentials credentials) {
                this.credentials = credentials;
            }
        }

        public static class KeystoneCredentials {
            private String username;
            private String password;

            public KeystoneCredentials(String username, String password) {
                super();
                this.username = username;
                this.password = password;
            }

            public String getUsername() {
                return username;
            }

            public void setUsername(String username) {
                this.username = username;
            }

            public String getPassword() {
                return password;
            }

            public void setPassword(String password) {
                this.password = password;
            }

        }

    }

    public static class KeystoneV3AuthenticationRequest implements KeystoneAuthenticationRequest{
        private KeystoneIdentity identity;

        public KeystoneV3AuthenticationRequest(String domain, String username, String password) {
            identity = new KeystoneIdentity(new KeystoneAuthentication(domain, username, password));
        }

        @JsonProperty("auth")
        public KeystoneIdentity getIdentity() {
            return identity;
        }

        public static class KeystoneIdentity {
            public KeystoneIdentity(KeystoneAuthentication auth) {
                this.auth = auth;
            }

            private KeystoneAuthentication auth;
            @JsonProperty("identity")
            public KeystoneAuthentication getAuth() {
                return auth;
            }

            @JsonProperty("identity")
            public void setAuth(KeystoneAuthentication auth) {
                this.auth = auth;
            }

        }

        public static class KeystoneAuthentication {
            private String[] methods = new String[] {"password"};
            private String domain;
            private KeystoneCredentials credentials;

            public KeystoneAuthentication(String domain, String username, String password) {
                this.domain = domain;
                this.credentials = new KeystoneCredentials(username, password);
            }

            @JsonProperty("methods")
            public String[] getMethods() {
                return methods;
            }

            @JsonProperty("methods")
            public void setMethods(String[] methods) {
                this.methods = methods;
            }

            @JsonProperty("password")
            public KeystoneCredentials getCredentials() {
                return credentials;
            }

            @JsonProperty("password")
            public void setCredentials(KeystoneCredentials credentials) {
                this.credentials = credentials;
            }
        }

        public static class KeystoneCredentials {

            private KeystoneUser user;
            public KeystoneCredentials(String username, String password) {
                user = new KeystoneUser(username, password);
            }

            public KeystoneUser getUser() {
                return user;
            }

            public void setUser(KeystoneUser user) {
                this.user = user;
            }
        }

        public static class KeystoneUser {
            private String name;
            private String password;

            public KeystoneUser(String name, String password) {
                this.name = name;
                this.password = password;
            }

            public KeystoneDomain getDomain() {
                return new KeystoneDomain();
            }

            public String getName() {
                return name;
            }

            public void setName(String name) {
                this.name = name;
            }

            public String getPassword() {
                return password;
            }

            public void setPassword(String password) {
                this.password = password;
            }

        }

        public static class KeystoneDomain {
            public String getName() {
                return "Default";
            }
        }

    }

}
