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
package org.cloudfoundry.identity.uaa.client;

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Customized {@code UserDetails} implementation.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */

public class SocialClientUserDetails extends AbstractAuthenticationToken {

    public static class Source {

        public static String CLOUD_FOUNDRY = "cloudfoundry";

        public static String GITHUB = "github";

        public static String FACEBOOK = "facebook";

        public static String TWITTER = "twitter";

        public static String LINKEDIN = "linkedin";

        public static String GOOGLE = "google";

        public static String classify(String userInfoUrl) {
            String key = userInfoUrl.toLowerCase().replaceAll(".*//([a-z.]*)/.*", "$1");
            if (userInfoUrl.contains("cloudfoundry.com")) {
                key = CLOUD_FOUNDRY;
            } else if (userInfoUrl.contains("google.com") || userInfoUrl.contains("googleapis.com")) {
                key = GOOGLE;
            } else if (userInfoUrl.contains("github.com")) {
                key = GITHUB;
            } else if (userInfoUrl.contains("twitter.com")) {
                key = TWITTER;
            } else if (userInfoUrl.contains("linkedin.com")) {
                key = LINKEDIN;
            } else {
                String[] keys = key.split("\\.");
                if (keys.length > 1) {
                    key = keys[keys.length - 2];
                }
                if ("co".equals(key) && keys.length > 2) {
                    key = keys[keys.length - 3];
                }
            }
            return key;
        }
    }

    private final String username;

    private String email;

    private String name;

    private Object id;

    private String source;

    @JsonCreator
    public SocialClientUserDetails(
            @JsonProperty("username") String username,
            @JsonProperty("authorities") @JsonDeserialize(contentAs = UaaAuthority.class) Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        setAuthenticated(authorities != null && !authorities.isEmpty());
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public Object getExternalId() {
        return id;
    }

    public void setExternalId(Object id) {
        this.id = id;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    @JsonIgnore
    public String getName() {
        // This is used as the principal name (which could then be used to look
        // up tokens etc)
        return username;
    }

    public void setFullName(String name) {
        this.name = name;
    }

    public String getFullName() {
        return this.name;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getUsername() {
        return username;
    }

    @JsonIgnore
    @Override
    public Object getCredentials() {
        return "N/A";
    }

    @JsonIgnore
    @Override
    public Object getPrincipal() {
        return this.username;
    }

    /*
     * {"details":"app",
     * "authorities":["UAA_USER"],
     * "authenticated":true,
     * "username":"marissa",
     * "email":null,
     * "name":"marissa",
     * "source":null,
     * "externalId":null,
     * "fullName":null,
     * "credentials":"N/A",
     * "principal":"marissa"}
     */
}
