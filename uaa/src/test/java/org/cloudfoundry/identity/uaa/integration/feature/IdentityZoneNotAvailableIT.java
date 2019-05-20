package org.cloudfoundry.identity.uaa.integration.feature;


import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class IdentityZoneNotAvailableIT {

    private RestTemplate restTemplate;

    private String zoneUrl;

    private String baseUrl = "http://localhost:8080/uaa";

    @Parameterized.Parameters(name = "{index}: zoneUrl[{0}];")
    public static List<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {"http://testzonedoesnotexist.localhost:8080/uaa"},
                {"http://testzoneinactive.localhost:8080/uaa"}
        });
    }

    public IdentityZoneNotAvailableIT(String zoneUrl) {
        this.zoneUrl = zoneUrl;
    }

    @Before
    public void setUp() throws Exception {
        String[] scope = {"uaa.admin"};
        ClientCredentialsResourceDetails adminResource = IntegrationTestUtils.getClientCredentialsResource(baseUrl, scope, "admin", "adminsecret");
        restTemplate = IntegrationTestUtils.getClientCredentialsTemplate(
                adminResource);
        restTemplate.setRequestFactory(new IntegrationTestUtils.StatelessRequestFactory());
        restTemplate.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
            }
        });
        IntegrationTestUtils.createInactiveIdentityZone(restTemplate, baseUrl);
    }

    @Test
    public void testTokenKeysEndpoint() {
        checkNotFoundForEndpoint(HttpMethod.GET, zoneUrl + "/token_keys");
    }

    @Test
    public void testTokenKeyEndpoint() {
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/token_key");
    }

    @Test
    public void testLogoutDo() {
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/logout.do");
    }

    @Test
    public void testIdentityProvidersEndpoints() {
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/identity-providers");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/identity-providers");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/identity-providers/id");
        checkNotFoundForEndpoint(HttpMethod.PUT,zoneUrl + "/identity-providers/id");
        checkNotFoundForEndpoint(HttpMethod.DELETE,zoneUrl + "/identity-providers/id");
        checkNotFoundForEndpoint(HttpMethod.PATCH,zoneUrl + "/identity-providers/id/status");
    }

    @Test
    public void testSamlServiceProvidersEndpoints() {
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/saml/idp/initiate");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/saml/service-providers");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/saml/service-providers/id");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/saml/service-providers");
        checkNotFoundForEndpoint(HttpMethod.PUT,zoneUrl + "/saml/service-providers/id");
        checkNotFoundForEndpoint(HttpMethod.DELETE,zoneUrl + "/saml/service-providers/id");
    }

    @Test
    public void testMfaProvidersEndpoints() {
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/mfa-providers");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/mfa-providers/id");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/mfa-providers");
        checkNotFoundForEndpoint(HttpMethod.DELETE,zoneUrl + "/mfa-providers/id");
    }

    @Test
    public void testUsersEndpoints() {
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/Users/id");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/Users");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/Users");
        checkNotFoundForEndpoint(HttpMethod.PUT,zoneUrl + "/Users/id");
        checkNotFoundForEndpoint(HttpMethod.PATCH,zoneUrl + "/Users/id");
        checkNotFoundForEndpoint(HttpMethod.DELETE,zoneUrl + "/Users/id");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/userinfo");
        checkNotFoundForEndpoint(HttpMethod.PUT,zoneUrl + "/Users/id/password");
        checkNotFoundForEndpoint(HttpMethod.PATCH,zoneUrl + "/Users/id/status");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/Users/id/verify-link");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/Users/id/verify");
        checkNotFoundForEndpoint(HttpMethod.DELETE,zoneUrl + "/Users/id/mfa");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/ids/Users");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/invite_users");
    }

    @Test
    public void testGroupsEndpoints() {
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/Groups/id");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/Groups");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/Groups");
        checkNotFoundForEndpoint(HttpMethod.PUT,zoneUrl + "/Groups/id");
        checkNotFoundForEndpoint(HttpMethod.PATCH,zoneUrl + "/Groups/id");
        checkNotFoundForEndpoint(HttpMethod.DELETE,zoneUrl + "/Groups/id");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/Groups/id1/members/id2");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/Groups/id1/members");
        checkNotFoundForEndpoint(HttpMethod.DELETE,zoneUrl + "/Groups/id1/members/id2");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/Groups/id1/members");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/Groups/External");
        checkNotFoundForEndpoint(HttpMethod.DELETE,zoneUrl + "/Groups/External/groupId/id");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/Groups/External");
    }

    @Test
    public void testClientsEndpoints() {
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/oauth/clients/id");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/oauth/clients");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/oauth/clients");
        checkNotFoundForEndpoint(HttpMethod.PUT,zoneUrl + "/oauth/clients/id");
        checkNotFoundForEndpoint(HttpMethod.DELETE,zoneUrl + "/oauth/clients/id");
        checkNotFoundForEndpoint(HttpMethod.PUT,zoneUrl + "/oauth/clients/id/secret");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/oauth/clients/tx");
        checkNotFoundForEndpoint(HttpMethod.PUT,zoneUrl + "/oauth/clients/tx");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/oauth/clients/tx/secret");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/oauth/clients/tx/modify");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/oauth/clients/tx/delete");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/oauth/clients/id/meta");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/oauth/clients/meta");
        checkNotFoundForEndpoint(HttpMethod.PUT,zoneUrl + "/oauth/clients/id/meta");
    }

    @Test
    public void testServerInformationEndpoints() {
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/info");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/passcode");
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/autologin");
        checkNotFoundForEndpoint(HttpMethod.GET,zoneUrl + "/autologin");
    }

    @Test
    public void testExternalLoginServerEndpoints() {
        checkNotFoundForEndpoint(HttpMethod.POST,zoneUrl + "/password_resets");
    }

    @Test
    public void testStaticContentFound() {
        HttpMethod method  = HttpMethod.GET;
        String endpoint  = zoneUrl + "/resources/oss/stylesheets/application.css";

        ResponseEntity<Void> forEntity = restTemplate.exchange(endpoint, method, new HttpEntity<Void>(null, new HttpHeaders()), Void.class);
        assertEquals(HttpStatus.OK, forEntity.getStatusCode());
    }

    private void checkNotFoundForEndpoint(HttpMethod method, String endpoint) {
        ResponseEntity<Void> forEntity = restTemplate.exchange(endpoint, method, new HttpEntity<Void>(null, new HttpHeaders()), Void.class);
        assertEquals(HttpStatus.NOT_FOUND, forEntity.getStatusCode());
    }
}
