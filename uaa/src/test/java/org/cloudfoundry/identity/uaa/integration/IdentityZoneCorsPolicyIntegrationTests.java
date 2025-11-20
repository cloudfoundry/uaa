package org.cloudfoundry.identity.uaa.integration;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.assertSupportsZoneDNS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.zone.CorsConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.web.client.RestTemplate;

@OAuth2ContextConfiguration(IdentityZoneCorsPolicyIntegrationTests.IdentityClient.class)
public class IdentityZoneCorsPolicyIntegrationTests {
    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);

    private final String zoneId = "zone-with-cors-policy";
    private final String zoneUrl = "http://" + zoneId + ".localhost:8080/uaa";

    private RestTemplate client;

    @Before
    public void setup() {
        assertSupportsZoneDNS();
        client = (OAuth2RestTemplate) serverRunning.getRestTemplate();
        client.setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
            }
        });
        createZoneWithXHRCorsPolicy();
    }

    private void createZoneWithXHRCorsPolicy() {
        String requestBody =
            "{\"id\":\""+ zoneId +"\", \"subdomain\":\""+ zoneId +"\", \"name\":\"testCreateZone() "+ zoneId +"\", " +
            "\"config\": {\"corsPolicy\":{\"xhrConfiguration\":{\"allowedUris\":[\"^/uaa/login$\"]," +
            "\"allowedHeaders\":[\"Accept\",\"Authorization\",\"Content-Type\",\"Origin\",\"X-Requested-With\"]}}}}";

        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        ResponseEntity<IdentityZone> response = client.exchange(
            serverRunning.getUrl("/identity-zones"),
            HttpMethod.POST,
            new HttpEntity<>(requestBody, headers),
            new ParameterizedTypeReference<IdentityZone>() {});

        assertEquals(HttpStatus.CREATED, response.getStatusCode());

        CorsConfiguration xhrConfiguration = response.getBody().getConfig().getCorsPolicy().getXhrConfiguration();
        assertNotNull(xhrConfiguration);
        assertTrue(xhrConfiguration.getAllowedUris().contains("^/uaa/login$"));
    }

    @Test
    public void testZoneXHRCorsPolicyEnforced() {
        //non-cross-origin request should not trigger cors policy
        assertEquals(HttpStatus.OK, client.exchange(
            zoneUrl + "/info",
            HttpMethod.GET,
            new HttpEntity<>(null, new HttpHeaders()),
            new ParameterizedTypeReference<Void>() { }).getStatusCode());

        //cross-origin xhr request should trigger xhr cors policy
        HttpHeaders headers = new HttpHeaders();
        headers.add("Origin", "examples.com");
        headers.add("X-Requested-With", "com.ge.ent.MobileAPM");
        assertEquals(HttpStatus.FORBIDDEN, client.exchange(
            zoneUrl + "/info",
            HttpMethod.GET,
            new HttpEntity<>(null, headers),
            new ParameterizedTypeReference<Void>() { }).getStatusCode());
    }

    static class IdentityClient extends ClientCredentialsResourceDetails {
        public IdentityClient(Object target) {
            IdentityZoneCorsPolicyIntegrationTests test = (IdentityZoneCorsPolicyIntegrationTests) target;
            ClientCredentialsResourceDetails resource = test.testAccounts.getClientCredentialsResource(
                new String[] {"zones.write"}, "identity", "identitysecret");
            setClientId(resource.getClientId());
            setClientSecret(resource.getClientSecret());
            setId(getClientId());
            setAccessTokenUri(test.serverRunning.getAccessTokenUri());
        }
    }
}
