/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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
import org.cloudfoundry.identity.uaa.authentication.NonStringPassword;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.Map;

public class KeystoneAuthenticationManager extends RestAuthenticationManager {

    public KeystoneAuthenticationManager() {
    }

    @Override
    protected HttpHeaders getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        return headers;
    }

    @Override
    protected boolean evaluateResponse(Authentication authentication, ResponseEntity<Map> response) {
        boolean v2 = true;
        Map<String, Object> map = (Map<String, Object>) response.getBody().get("access");
        if (map == null) {
            v2 = false;
            map = (Map<String, Object>) response.getBody().get("token");
        }
        Map<String, Object> user = (Map<String, Object>) map.get("user");
        return authentication.getPrincipal().toString().equals(user.get(v2 ? "username" : "name"));
    }

    @Override
    protected KeystoneAuthenticationRequest getParameters(String username, String password) {
        if (getRemoteUrl() != null && getRemoteUrl().contains("/v2.0")) {
            return new KeystoneV2AuthenticationRequest("", username, password);
        } else if (getRemoteUrl() != null && getRemoteUrl().contains("/v3")) {
            return new KeystoneV3AuthenticationRequest("", username, password);
        } else {
            throw new UnsupportedOperationException("Unable to determine API version:" + getRemoteUrl());
        }

    }


    public interface KeystoneAuthenticationRequest {
    }

    // Manual creation, but must support JSON serialization - does NOT support direct binding from JSON (no default constructors)
    public static class KeystoneV2AuthenticationRequest implements KeystoneAuthenticationRequest {
        private final KeystoneAuthentication auth;

        public KeystoneV2AuthenticationRequest(String tenant, String username, String password) {
            auth = new KeystoneAuthentication(tenant, username, password);
        }

        @JsonProperty("auth")
        public KeystoneAuthentication getAuth() {
            return auth;
        }

        public static class KeystoneAuthentication {
            private final String tenant;
            private final KeystoneCredentials credentials;

            public KeystoneAuthentication(String tenant, String username, String password) {
                this.tenant = tenant;
                this.credentials = new KeystoneCredentials(username, password);
            }

            @JsonProperty("tenantName")
            public String getTenant() {
                return tenant;
            }

            @JsonProperty("passwordCredentials")
            public KeystoneCredentials getCredentials() {
                return credentials;
            }
        }

        public static class KeystoneCredentials extends NonStringPassword {
            private final String username;

            public KeystoneCredentials(String username, String password) {
                super(password);
                this.username = username;
            }

            @JsonProperty("username")
            public String getUsername() {
                return username;
            }
        }

    }

    // Manual creation, but must support JSON serialization - does NOT support direct binding from JSON (no default constructors)
    public static class KeystoneV3AuthenticationRequest implements KeystoneAuthenticationRequest {
        private final KeystoneIdentity identity;

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

            private final KeystoneAuthentication auth;

            @JsonProperty("identity")
            public KeystoneAuthentication getAuth() {
                return auth;
            }
        }

        @SuppressWarnings({"FieldCanBeLocal", "unused"})
        public static class KeystoneAuthentication {
            private final String[] methods = new String[]{"password"};
            private final String domain; // No getter and no toString? assuming needed for JSON object
            private final KeystoneCredentials credentials;

            public KeystoneAuthentication(String domain, String username, String password) {
                this.domain = domain;
                this.credentials = new KeystoneCredentials(username, password);
            }

            @JsonProperty("methods")
            public String[] getMethods() {
                return methods;
            }

            @JsonProperty("password")
            public KeystoneCredentials getCredentials() {
                return credentials;
            }
        }

        public static class KeystoneCredentials {
            private final KeystoneUser user;

            public KeystoneCredentials(String username, String password) {
                user = new KeystoneUser(username, password);
            }

            public KeystoneUser getUser() {
                return user;
            }
        }

        public static class KeystoneUser extends NonStringPassword {
            private final String name;

            public KeystoneUser(String name, String password) {
                super(password);
                this.name = name;
            }

            public KeystoneDomain getDomain() {
                return new KeystoneDomain();
            }

            @JsonProperty("username")
            public String getName() {
                return name;
            }
        }

        public static class KeystoneDomain {
            public String getName() {
                return "Default";
            }
        }

    }

}
