package org.cloudfoundry.identity.uaa.login.util;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.message.LocalUaaRestTemplate;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Method;
import java.net.URI;

import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.*;

@DefaultTestContext
class LocalUaaRestTemplateMockMvcTests {

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    private LocalUaaRestTemplate localUaaRestTemplate;

    @Test
    void localUaaRestTemplateAcquireToken() {
        OAuth2AccessToken token = localUaaRestTemplate.acquireAccessToken(new DefaultOAuth2ClientContext());
        assertTrue("Scopes should contain oauth.login", token.getScope().contains("oauth.login"));
        assertTrue("Scopes should contain notifications.write", token.getScope().contains("notifications.write"));
        assertTrue("Scopes should contain critical_notifications.write", token.getScope().contains("critical_notifications.write"));
    }

    @Test
    void uaaRestTemplateContainsBearerHeader() throws Exception {
        OAuth2AccessToken token = localUaaRestTemplate.acquireAccessToken(localUaaRestTemplate.getOAuth2ClientContext());
        Method createRequest = OAuth2RestTemplate.class.getDeclaredMethod("createRequest", URI.class, HttpMethod.class);
        ReflectionUtils.makeAccessible(createRequest);
        ClientHttpRequest request = (ClientHttpRequest) createRequest.invoke(localUaaRestTemplate, new URI("http://localhost/oauth/token"), HttpMethod.POST);
        assertEquals("authorization bearer header should be present", 1, request.getHeaders().get("Authorization").size());
        assertNotNull("authorization bearer header should be present", request.getHeaders().get("Authorization").get(0));
        assertThat(request.getHeaders().get("Authorization").get(0).toLowerCase(), startsWith("bearer "));
        assertThat(request.getHeaders().get("Authorization").get(0), endsWith(token.getValue()));
    }
}
