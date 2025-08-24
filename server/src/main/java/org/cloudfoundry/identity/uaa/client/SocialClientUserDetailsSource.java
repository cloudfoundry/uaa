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

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.client.SocialClientUserDetails.Source;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;

/**
 * <p>
 * Helper class to extract user details from a remote endpoint, triggering
 * authentication and approval if necessary by throwing an appropriate
 * exception. The exception and how it should be handled depends on the
 * authorization protocol in use (a RestTemplate implementation is usually
 * paired with a client-side filter that handles redirects to the provider).
 * </p>
 * 
 * <p>
 * Tested with Facebook, Github, Cloudfoundry, Twitter, LinkedIn. Should work
 * with other providers if they use the same conventions in their user info
 * endpoint. Note that the amount of information contained in the resulting
 * {@link SocialClientUserDetails} depends on the provider and also on the
 * user's preferences with the provider (e.g. he may have chosen not to reveal
 * his email in github, in which case the user details will not have an email
 * address).
 * </p>
 * 
 * @author Dave Syer
 * 
 */
public class SocialClientUserDetailsSource implements InitializingBean, PreAuthenticatedPrincipalSource<Authentication> {

    private RestOperations restTemplate;

    private String userInfoUrl;

    /**
     * A rest template to be used to contact the remote user info endpoint.
     * Normally would be an instance of {@link OAuth2RestTemplate}, but there is
     * no need for that dependency to be explicit, and there are advantages in
     * making it implicit (e.g. for testing purposes).
     * 
     * @param restTemplate a rest template
     */
    public void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * The remote URL of the <code>/userinfo</code> endpoint or equivalent. This
     * should be a resource on the remote
     * server that provides user profile data.
     * 
     * @param userInfoUrl
     */
    public void setUserInfoUrl(String userInfoUrl) {
        this.userInfoUrl = userInfoUrl;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.state(userInfoUrl != null, "User info URL must be provided");
        Assert.state(restTemplate != null, "RestTemplate URL must be provided");
    }

    /**
     * Get as much generic information as possible about the current user from
     * the remote endpoint. The aim is to
     * collect as much of the properties of a {@link SocialClientUserDetails} as
     * possible but not to fail if there is an
     * authenticated user. If one of the tested remote providers is used at
     * least a user id will be available, asserting
     * that someone has authenticated and permitted us to see some public
     * information.
     * 
     * @return some user details
     */
    @Override
    public Authentication getPrincipal() {
        @SuppressWarnings("unchecked")
        Map<String, String> map = restTemplate.getForObject(userInfoUrl, Map.class);
        if (map == null) {
            map = Collections.emptyMap();
        }
        String userName = getUserName(map);
        String email = null;
        if (map.containsKey("email")) {
            email = map.get("email");
        }
        if (userName == null && email != null) {
            userName = email;
        }
        if (userName == null) {
            userName = map.get("id"); // no user-friendly identifier for linked
            // in and google
        }
        List<UaaAuthority> authorities = UaaAuthority.USER_AUTHORITIES;
        SocialClientUserDetails user = new SocialClientUserDetails(userName, authorities);
        user.setSource(Source.classify(userInfoUrl));
        user.setExternalId(getUserId(map));
        String fullName = getFullName(map);
        if (fullName != null) {
            user.setFullName(fullName);
        }
        if (email != null) {
            user.setEmail(email);
        }
        return user;
    }

    private String getFullName(Map<String, String> map) {
        if (map.containsKey("name")) {
            return map.get("name");
        }
        if (map.containsKey("formattedName")) {
            return map.get("formattedName");
        }
        if (map.containsKey("fullName")) {
            return map.get("fullName");
        }
        String firstName = null;
        if (map.containsKey("firstName")) {
            firstName = map.get("firstName");
        }
        if (map.containsKey("givenName")) {
            firstName = map.get("givenName");
        }
        String lastName = null;
        if (map.containsKey("lastName")) {
            lastName = map.get("lastName");
        }
        if (map.containsKey("familyName")) {
            lastName = map.get("familyName");
        }
        if (firstName != null) {
            if (lastName != null) {
                return firstName + " " + lastName;
            }
        }
        return null;
    }

    private Object getUserId(Map<String, String> map) {
        String key = "id";
        if (userInfoUrl.contains("run.pivotal.io")) {
            key = "user_id";
        }
        return map.get(key);
    }

    private String getUserName(Map<String, String> map) {
        String key = "username";
        if (map.containsKey(key)) {
            return map.get(key);
        }
        if (userInfoUrl.contains("run.pivotal.io") || userInfoUrl.endsWith("/uaa/userinfo")) {
            key = "user_name";
        }
        if (userInfoUrl.contains("github.com")) {
            key = "login";
        }
        if (userInfoUrl.contains("twitter.com")) {
            key = "screen_name";
        }
        return map.get(key);
    }

}
