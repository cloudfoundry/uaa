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

import org.cloudfoundry.identity.uaa.oauth.client.DefaultOAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.AuthenticationScheme;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

/**
 * Tests some real internet-based OAuth2 user info providers. To run these tests
 * you need to get access tokens for the
 * relevant providers and set them up as system properties.
 *
 * @author Dave Syer
 */
class OAuth2ClientAuthenticationFilterTests {

    private final SocialClientUserDetailsSource filter = new SocialClientUserDetailsSource();

    private final OAuth2ClientContext context = new DefaultOAuth2ClientContext();

    private void setUpContext(String tokenName) {
        String accessToken = System.getProperty(tokenName);
        assumeThat(accessToken).isNotNull();
        context.setAccessToken(new DefaultOAuth2AccessToken(accessToken));
    }

    @Test
    void cloudFoundryAuthentication() {
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(new AuthorizationCodeResourceDetails(), context);
        setUpContext("cf.token");
        filter.setRestTemplate(restTemplate);
        filter.setUserInfoUrl("https://uaa.cloudfoundry.com/userinfo");
        filter.afterPropertiesSet();
        SocialClientUserDetails user = (SocialClientUserDetails) filter.getPrincipal();
        assertThat(user.getAuthorities()).isNotEmpty();
    }

    @Test
    void githubAuthentication() {
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(new AuthorizationCodeResourceDetails(), context);
        setUpContext("github.token");
        filter.setRestTemplate(restTemplate);
        filter.setUserInfoUrl("https://api.github.com/user");
        filter.afterPropertiesSet();
        SocialClientUserDetails user = (SocialClientUserDetails) filter.getPrincipal();
        assertThat(user.getAuthorities()).isNotEmpty();
    }

    @Test
    void facebookAuthentication() {
        AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
        resource.setAuthenticationScheme(AuthenticationScheme.query);
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resource, context);
        setUpContext("facebook.token");
        filter.setRestTemplate(restTemplate);
        filter.setUserInfoUrl("https://graph.facebook.com/me");
        filter.afterPropertiesSet();
        SocialClientUserDetails user = (SocialClientUserDetails) filter.getPrincipal();
        assertThat(user.getAuthorities()).isNotEmpty();
    }
}
