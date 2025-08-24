package org.cloudfoundry.identity.uaa.login.util;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.UaaProperties;
import org.cloudfoundry.identity.uaa.login.NotificationsProperties;
import org.cloudfoundry.identity.uaa.message.LocalUaaRestTemplate;
import org.cloudfoundry.identity.uaa.oauth.client.DefaultOAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Method;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

@DefaultTestContext
class LocalUaaRestTemplateMockMvcTests {

    private LocalUaaRestTemplate localUaaRestTemplate;

    @Autowired
    private AuthorizationServerTokenServices authorizationServerTokenServices;

    @Autowired
    private MultitenantClientServices multitenantClientServices;

    @Autowired
    private IdentityZoneManager identityZoneManager;

    @Autowired
    private UaaProperties.RootLevel uaaProperties;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        localUaaRestTemplate = new LocalUaaRestTemplate(
                uaaProperties,
                new NotificationsProperties("", true, false),
                authorizationServerTokenServices,
                multitenantClientServices,
                identityZoneManager
        );
    }

    @Test
    void localUaaRestTemplateAcquireToken() {
        OAuth2AccessToken token = localUaaRestTemplate.acquireAccessToken(new DefaultOAuth2ClientContext());
        assertThat(token.getScope()).as("Scopes should contain oauth.login").contains("oauth.login")
                .as("Scopes should contain notifications.write").contains("notifications.write")
                .as("Scopes should contain critical_notifications.write").contains("critical_notifications.write");
    }

    @Test
    void uaaRestTemplateContainsBearerHeader() throws Exception {
        OAuth2AccessToken token = localUaaRestTemplate.acquireAccessToken(localUaaRestTemplate.getOAuth2ClientContext());
        Method createRequest = OAuth2RestTemplate.class.getDeclaredMethod("createRequest", URI.class, HttpMethod.class);
        ReflectionUtils.makeAccessible(createRequest);
        ClientHttpRequest request = (ClientHttpRequest) createRequest.invoke(localUaaRestTemplate, new URI("http://localhost/oauth/token"), HttpMethod.POST);
        assertThat(request.getHeaders().get("Authorization")).as("authorization bearer header should be present").hasSize(1);
        assertThat(request.getHeaders().get("Authorization").getFirst()).as("authorization bearer header should be present").isNotNull();
        assertThat(request.getHeaders().get("Authorization").getFirst().toLowerCase()).startsWith("bearer ");
        assertThat(request.getHeaders().get("Authorization").getFirst()).endsWith(token.getValue());
    }
}
