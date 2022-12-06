package org.cloudfoundry.identity.uaa.integration;

import static org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService.X_IDENTITY_ZONE_ID;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.UUID;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
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

@OAuth2ContextConfiguration(OrchestratorZoneControllerIntegrationTests.ZoneClient.class)
public class OrchestratorZoneControllerIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    private RestTemplate client;

    @Before
    public void createRestTemplate() {
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
    }

    @Test
    public void testGetZone() {
        //TODO: delete once the orchestrator create API implemented
        IdentityZone identityZone = createZone();
        assertNotNull(identityZone);
        ResponseEntity<OrchestratorZoneResponse> response = client.getForEntity(
            serverRunning.getUrl("/orchestrator/zones") + "?name=" + identityZone.getName(),
            OrchestratorZoneResponse.class);
        if (response.getStatusCode().is2xxSuccessful()) {
            OrchestratorZoneResponse zoneResponse = response.getBody();
            assertNotNull(zoneResponse);
            assertNotNull(identityZone);
            assertNotNull(zoneResponse.getParameters());
            assertEquals(identityZone.getSubdomain(), zoneResponse.getParameters().getSubdomain());
            assertEquals(identityZone.getSubdomain(), zoneResponse.getConnectionDetails().getSubdomain());
            String uri = "http://" + identityZone.getSubdomain() + ".localhost:8080/uaa";
            assertEquals(uri, zoneResponse.getConnectionDetails().getUri());
            assertEquals("http://localhost:8080/dashboard", zoneResponse.getConnectionDetails().getDashboardUri());
            assertEquals(uri + "/oauth/token", zoneResponse.getConnectionDetails().getIssuerId());
            assertEquals(X_IDENTITY_ZONE_ID, zoneResponse.getConnectionDetails().getZone().getHttpHeaderName());
            assertEquals(identityZone.getId(), zoneResponse.getConnectionDetails().getZone().getHttpHeaderValue());
        } else {
            fail("Server not returning expected status code");
        }
    }

    @Test
    public void testGetZone_Notfound() {
        ResponseEntity<String> response = client.getForEntity(
            serverRunning.getUrl("/orchestrator/zones") + "?name=random-name",
            String.class);
        if (response.getStatusCode().is4xxClientError()) {
            assertEquals(response.getStatusCode(), HttpStatus.NOT_FOUND);
            assertNotNull(response.getBody());
            assertEquals("{\"message\", \"Zone[random-name] not found.\" }", response.getBody());
        } else {
            fail("Server not returning expected status code");
        }
    }

    @Test
    public void testGetZone_EmptyError() {
        ResponseEntity<String> response = client.getForEntity(
            serverRunning.getUrl("/orchestrator/zones"),
            String.class);
        if (response.getStatusCode().is4xxClientError()) {
            assertEquals(response.getStatusCode(), HttpStatus.BAD_REQUEST);
            assertNotNull(response.getBody());
            assertEquals(
                "{\"message\", \"Required request parameter 'name' for method parameter type String is not present\" }",
                response.getBody());
        } else {
            fail("Server not returning expected status code");
        }
    }

    @Test
    public void testGetZone_NameRequiredError() {
        ResponseEntity<String> response = client.getForEntity(
            serverRunning.getUrl("/orchestrator/zones") + "?name=",
            String.class);
        if (response.getStatusCode().is4xxClientError()) {
            assertEquals(response.getStatusCode(), HttpStatus.BAD_REQUEST);
            assertNotNull(response.getBody());
            assertEquals("{\"message\", \"getZone.name: must not be empty\" }", response.getBody());
        } else {
            fail("Server not returning expected status code");
        }
    }

    @Test
    public void testDeleteZone() {
        //TODO: delete once the orchestrator create API implemented
        IdentityZone identityZone = createZone();
        assertNotNull(identityZone);
        ResponseEntity<String> response =
            client.exchange(serverRunning.getUrl("/orchestrator/zones") + "?name=" + identityZone.getName(),
                            HttpMethod.DELETE, null, String.class);
        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        ResponseEntity<String> getResponse = client.getForEntity(
            serverRunning.getUrl("/orchestrator/zones") + "?name=" + identityZone.getName(),
            String.class);
        assertEquals(getResponse.getStatusCode(), HttpStatus.NOT_FOUND);
        assertNotNull(getResponse.getBody());
        assertEquals("{\"message\", \"Zone["+identityZone.getName()+"] not found.\" }", getResponse.getBody());
    }

    @Test
    public void testDeleteZone_NotFound() {
        ResponseEntity<String> response =
            client.exchange(serverRunning.getUrl("/orchestrator/zones") + "?name=random-name",
                            HttpMethod.DELETE, null, String.class);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("{\"message\", \"Zone[random-name] not found.\" }", response.getBody());
    }

    @Test
    public void testUpdateZone() {
        OrchestratorZoneRequest zoneRequest = new OrchestratorZoneRequest();
        zoneRequest.setName("test name");
        zoneRequest.setParameters(new OrchestratorZone());
        ResponseEntity<String> getResponse = client.exchange(
            serverRunning.getUrl("/orchestrator/zones"), HttpMethod.PUT, new HttpEntity<>(zoneRequest),
            String.class);
        assertEquals(getResponse.getStatusCode(), HttpStatus.METHOD_NOT_ALLOWED);
        assertNotNull(getResponse.getBody());
        assertEquals("{\"message\", \"Put Operation not Supported\" }", getResponse.getBody());
    }

    //TODO: delete once the orchestrator create API implemented
    private IdentityZone createZone() {
        String zoneId = UUID.randomUUID().toString();
        String requestBody =
            "{\"id\":\"" + zoneId + "\", \"subdomain\":\"" + zoneId + "\", \"name\":\"testCreateZone() " + zoneId +
            "\"}";

        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        ResponseEntity<IdentityZone> response = client.exchange(
            serverRunning.getUrl("/identity-zones"),
            HttpMethod.POST,
            new HttpEntity<>(requestBody, headers),
            new ParameterizedTypeReference<IdentityZone>() { });
        if (response.getStatusCode().is2xxSuccessful()) {
            return response.getBody();
        }
        return null;
    }

    static class ZoneClient extends ClientCredentialsResourceDetails {

        public ZoneClient(Object target) {
            OrchestratorZoneControllerIntegrationTests test = (OrchestratorZoneControllerIntegrationTests) target;
            ClientCredentialsResourceDetails resource = test.testAccounts.getClientCredentialsResource(
                new String[] { "zones.write" }, "identity", "identitysecret");
            setClientId(resource.getClientId());
            setClientSecret(resource.getClientSecret());
            setId(getClientId());
            setAccessTokenUri(test.serverRunning.getAccessTokenUri());
        }
    }
}
