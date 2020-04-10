

package org.cloudfoundry.identity.uaa.client;

import static org.junit.Assert.assertTrue;

import org.junit.Assume;
import org.junit.Test;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;

/**
 * Tests some real internet-based OAuth2 user info providers. To run these tests
 * you need to get access tokens for the
 * relevant providers and set them up as system properties.
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2ClientAuthenticationFilterTests {

    private SocialClientUserDetailsSource filter = new SocialClientUserDetailsSource();

    private OAuth2ClientContext context = new DefaultOAuth2ClientContext();

    private void setUpContext(String tokenName) {
        String accessToken = System.getProperty(tokenName);
        Assume.assumeNotNull(accessToken);
        context.setAccessToken(new DefaultOAuth2AccessToken(accessToken));
    }

    @Test
    public void testCloudFoundryAuthentication() {
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(new AuthorizationCodeResourceDetails(), context);
        setUpContext("cf.token");
        filter.setRestTemplate(restTemplate);
        filter.setUserInfoUrl("https://uaa.cloudfoundry.com/userinfo");
        filter.afterPropertiesSet();
        SocialClientUserDetails user = (SocialClientUserDetails) filter.getPrincipal();
        assertTrue(!user.getAuthorities().isEmpty());
    }

    @Test
    public void testGithubAuthentication() {
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(new AuthorizationCodeResourceDetails(), context);
        setUpContext("github.token");
        filter.setRestTemplate(restTemplate);
        filter.setUserInfoUrl("https://api.github.com/user");
        filter.afterPropertiesSet();
        SocialClientUserDetails user = (SocialClientUserDetails) filter.getPrincipal();
        assertTrue(!user.getAuthorities().isEmpty());
    }

    @Test
    public void testFacebookAuthentication() {
        AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
        resource.setAuthenticationScheme(AuthenticationScheme.query);
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resource, context);
        setUpContext("facebook.token");
        filter.setRestTemplate(restTemplate);
        filter.setUserInfoUrl("https://graph.facebook.com/me");
        filter.afterPropertiesSet();
        SocialClientUserDetails user = (SocialClientUserDetails) filter.getPrincipal();
        assertTrue(!user.getAuthorities().isEmpty());
    }

}
