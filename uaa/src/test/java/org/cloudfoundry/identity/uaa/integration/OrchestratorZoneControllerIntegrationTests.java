package org.cloudfoundry.identity.uaa.integration;

import static org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService.X_IDENTITY_ZONE_ID;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8;

import java.util.UUID;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorErrorResponse;
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

    public static final String ZONE_NAME = "The Twiglet Zone";
    public static final String SUB_DOMAIN_NAME = "sub-domain-01";
    public static final String ADMIN_CLIENT_SECRET = "admin-secret-01";

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
        String zoneName = createZoneGetZoneName();
        ResponseEntity<OrchestratorZoneResponse> response = client.getForEntity(
            serverRunning.getUrl("/orchestrator/zones") + "?name=" + zoneName,
            OrchestratorZoneResponse.class);
        if (response.getStatusCode().is2xxSuccessful()) {
            OrchestratorZoneResponse zoneResponse = response.getBody();
            assertNotNull(zoneResponse);
            assertNotNull(zoneResponse.getParameters());
            assertEquals(zoneName, zoneResponse.getParameters().getSubdomain());
            assertEquals(zoneName, zoneResponse.getConnectionDetails().getSubdomain());
            String uri = "http://" + zoneName + ".localhost:8080/uaa";
            assertEquals(uri, zoneResponse.getConnectionDetails().getUri());
            assertEquals("http://localhost:8080/dashboard", zoneResponse.getConnectionDetails().getDashboardUri());
            assertEquals(uri + "/oauth/token", zoneResponse.getConnectionDetails().getIssuerId());
            assertEquals(X_IDENTITY_ZONE_ID, zoneResponse.getConnectionDetails().getZone().getHttpHeaderName());
            assertNotNull(zoneResponse.getConnectionDetails().getZone().getHttpHeaderValue());
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
            assertEquals(APPLICATION_JSON_UTF8, response.getHeaders().getContentType());
            String expected  =  JsonUtils.writeValueAsString(
                new OrchestratorErrorResponse("Zone[random-name] not found."));
            assertEquals(expected, response.getBody());
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
            assertEquals(APPLICATION_JSON_UTF8, response.getHeaders().getContentType());
            String expected  =  JsonUtils.writeValueAsString(
                new OrchestratorErrorResponse("Required request parameter 'name' for method parameter type String is " +
                                              "not present"));
            assertEquals(expected, response.getBody());
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
            assertEquals(APPLICATION_JSON_UTF8, response.getHeaders().getContentType());
            String expected  =  JsonUtils.writeValueAsString(
                new OrchestratorErrorResponse("getZone.name: must not be empty"));
            assertEquals(expected, response.getBody());
        } else {
            fail("Server not returning expected status code");
        }
    }

    @Test
    public void testDeleteZone() {
        String zoneName = createZoneGetZoneName();
        ResponseEntity<String> response =
            client.exchange(serverRunning.getUrl("/orchestrator/zones") + "?name=" + zoneName,
                            HttpMethod.DELETE, null, String.class);
        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        ResponseEntity<String> getResponse = client.getForEntity(
            serverRunning.getUrl("/orchestrator/zones") + "?name=" + zoneName,
            String.class);
        assertEquals(getResponse.getStatusCode(), HttpStatus.NOT_FOUND);
        assertNotNull(getResponse.getBody());
        assertEquals(APPLICATION_JSON_UTF8, getResponse.getHeaders().getContentType());
        String expected  =  JsonUtils.writeValueAsString(
            new OrchestratorErrorResponse("Zone["+zoneName+"] not found."));
        assertEquals(expected, getResponse.getBody());
    }

    @Test
    public void testDeleteZone_NotFound() {
        ResponseEntity<String> response =
            client.exchange(serverRunning.getUrl("/orchestrator/zones") + "?name=random-name",
                            HttpMethod.DELETE, null, String.class);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNotNull(response.getBody());
        String expected  =  JsonUtils.writeValueAsString(
            new OrchestratorErrorResponse("Zone[random-name] not found."));
        assertEquals(expected, response.getBody());
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
        assertEquals(JsonUtils.writeValueAsString(
            new OrchestratorErrorResponse("Put Operation not Supported")), getResponse.getBody());
    }

    @Test
    public void testCreateZone() {
        String zoneName = getName();
        ResponseEntity<Void> response = createZone(zoneName);
        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    public void testCreateAndGetZone_SubdomainAsNULL_inRequestBody() {
        String zoneName = createZoneSubdomainAsNullInParameter();
        ResponseEntity<OrchestratorZoneResponse> getResponse = client.getForEntity(
            serverRunning.getUrl("/orchestrator/zones") + "?name=" + zoneName,
            OrchestratorZoneResponse.class);
        if (getResponse.getStatusCode().is2xxSuccessful()) {
            OrchestratorZoneResponse zoneResponse = getResponse.getBody();
            assertNotNull(zoneResponse);
            assertNull(zoneResponse.getParameters().getSubdomain());
            String connectionDetailSubdomain = zoneResponse.getConnectionDetails().getSubdomain();
            assertNotNull(connectionDetailSubdomain);
            String uri = "http://" + connectionDetailSubdomain + ".localhost:8080/uaa";
            assertEquals(uri, zoneResponse.getConnectionDetails().getUri());
            assertEquals("http://localhost:8080/dashboard", zoneResponse.getConnectionDetails().getDashboardUri());
            assertEquals(uri + "/oauth/token", zoneResponse.getConnectionDetails().getIssuerId());
            assertEquals(X_IDENTITY_ZONE_ID, zoneResponse.getConnectionDetails().getZone().getHttpHeaderName());
            assertEquals(connectionDetailSubdomain, zoneResponse.getConnectionDetails().getZone().getHttpHeaderValue());
        } else {
            fail("Server not returning expected status code");
        }
    }

    private String createZoneSubdomainAsNullInParameter() {
        String zoneName = getName();
        String requestBody = JsonUtils.writeValueAsString(getOrchestratorZoneRequest(zoneName,ADMIN_CLIENT_SECRET,
                                                                                     null));
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        ResponseEntity<Void> response = client.exchange(
            serverRunning.getUrl("/orchestrator/zones"),
            HttpMethod.POST,
            new HttpEntity<>(requestBody, headers), new ParameterizedTypeReference<Void>() {});

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertNull(response.getBody());
        return zoneName;
    }

    @Test
    public void testCreateZone_ZoneAlreadyExists() {
        OrchestratorZoneRequest orchestratorZoneRequest = getOrchestratorZoneRequest(ZONE_NAME,ADMIN_CLIENT_SECRET,
                                                                                     SUB_DOMAIN_NAME);
        client.exchange(
            serverRunning.getUrl("/orchestrator/zones"), HttpMethod.POST, new HttpEntity<>(orchestratorZoneRequest),
            String.class);

        ResponseEntity<String> getResponseAlreadyExist = client.exchange(
            serverRunning.getUrl("/orchestrator/zones"), HttpMethod.POST, new HttpEntity<>(orchestratorZoneRequest),
            String.class);
        assertEquals(getResponseAlreadyExist.getStatusCode(), HttpStatus.BAD_REQUEST);
        assertTrue(getResponseAlreadyExist.getBody().contains("Orchestrator zone already exists for name:  "+ZONE_NAME));
    }

    @Test
    public void testCreateZone_nameAsSpaceAndEmptyError() {
        testNameAsSpaceAndEmpty(getOrchestratorZoneRequest("",ADMIN_CLIENT_SECRET,SUB_DOMAIN_NAME));
        testNameAsSpaceAndEmpty(getOrchestratorZoneRequest("    ",ADMIN_CLIENT_SECRET,SUB_DOMAIN_NAME));
    }

    @Test
    public void testCreateZone_subDomainWithSpaceOrSpecialCharFail() {
        testWithSpaceOrSpecialCharFail(getOrchestratorZoneRequest(getName(),ADMIN_CLIENT_SECRET,
                                                                  "sub#-domain"));
        testWithSpaceOrSpecialCharFail(getOrchestratorZoneRequest(getName(),ADMIN_CLIENT_SECRET,
                                                                  "-subdomainStartsWithHYphen"));
        testWithSpaceOrSpecialCharFail(getOrchestratorZoneRequest(getName(),ADMIN_CLIENT_SECRET,
                                                                  "subdomainEndsWithHYphen-"));
        testWithSpaceOrSpecialCharFail(getOrchestratorZoneRequest(getName(),ADMIN_CLIENT_SECRET,
                                                                  "sub\\\\domaincontainsslash"));
        testWithSpaceOrSpecialCharFail(getOrchestratorZoneRequest(getName(),ADMIN_CLIENT_SECRET,
                                                                  "sub$%domaincontainsSpecialChars"));
    }

    @Test
    public void testCreateZone_adminClientSecretAsSpaceAndEmptyError() {
        testAdminClientSecretAsSpaceAndEmpty(getOrchestratorZoneRequest(getName(),"", SUB_DOMAIN_NAME));
        testAdminClientSecretAsSpaceAndEmpty(getOrchestratorZoneRequest(getName(),"    ", SUB_DOMAIN_NAME));
    }

    private void testAdminClientSecretAsSpaceAndEmpty(OrchestratorZoneRequest orchestratorZoneRequest) {
        ResponseEntity<String> getResponse = client.exchange(
            serverRunning.getUrl("/orchestrator/zones"), HttpMethod.POST, new HttpEntity<>(orchestratorZoneRequest),
            String.class);
        assertEquals(getResponse.getStatusCode(), HttpStatus.BAD_REQUEST);
        assertEquals(APPLICATION_JSON_UTF8, getResponse.getHeaders().getContentType());
        String expected  =  JsonUtils.writeValueAsString(
            new OrchestratorErrorResponse("The adminClientSecret field cannot contain" +
                                          " spaces or cannot be blank."));
        assertEquals(expected, getResponse.getBody());
    }

    private void testWithSpaceOrSpecialCharFail(OrchestratorZoneRequest orchestratorZoneRequest) {
        ResponseEntity<String> getResponse = client.exchange(
            serverRunning.getUrl("/orchestrator/zones"), HttpMethod.POST, new HttpEntity<>(orchestratorZoneRequest),
            String.class);
        assertEquals(getResponse.getStatusCode(), HttpStatus.BAD_REQUEST);
        assertTrue(getResponse.getBody().contains("Special characters are not allowed in the subdomain " +
                                                  "name except hyphen which can be specified in the middle."));
    }

    private void testNameAsSpaceAndEmpty(OrchestratorZoneRequest orchestratorZoneRequest) {
        ResponseEntity<String> getResponse = client.exchange(
            serverRunning.getUrl("/orchestrator/zones"), HttpMethod.POST, new HttpEntity<>(orchestratorZoneRequest),
            String.class);
        assertEquals(getResponse.getStatusCode(), HttpStatus.BAD_REQUEST);
        assertTrue(getResponse.getBody().contains("default message [name]]; default message [must not be empty]]"));
    }

    static class ZoneClient extends ClientCredentialsResourceDetails {

        public ZoneClient(Object target) {
            OrchestratorZoneControllerIntegrationTests test = (OrchestratorZoneControllerIntegrationTests) target;
            ClientCredentialsResourceDetails resource = test.testAccounts.getAdminClientCredentialsResource();
            setClientId(resource.getClientId());
            setClientSecret(resource.getClientSecret());
            setId(getClientId());
            setAccessTokenUri(test.serverRunning.getAccessTokenUri());
        }
    }

    private OrchestratorZoneRequest getOrchestratorZoneRequest(String name, String adminClientSecret,
                                                               String subdomain) {
        OrchestratorZone orchestratorZone = new OrchestratorZone(adminClientSecret, subdomain);
        OrchestratorZoneRequest orchestratorZoneRequest = new OrchestratorZoneRequest();
        orchestratorZoneRequest.setName(name);
        orchestratorZoneRequest.setParameters(orchestratorZone);
        return orchestratorZoneRequest;
    }

    private String getName() {
        String id = UUID.randomUUID().toString();
        return id;
    }

    private String createZoneGetZoneName() {
        String zoneName = getName();
        ResponseEntity<Void> createZoneResponse = createZone(zoneName);
        assertEquals(HttpStatus.ACCEPTED, createZoneResponse.getStatusCode());
        assertNull(createZoneResponse.getBody());
        return zoneName;
    }

    private ResponseEntity<Void> createZone(String zoneName) {
        String subDomain =  zoneName;
        String requestBody = JsonUtils.writeValueAsString(getOrchestratorZoneRequest(zoneName,ADMIN_CLIENT_SECRET, subDomain));
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        ResponseEntity<Void> response = client.exchange(
            serverRunning.getUrl("/orchestrator/zones"),
            HttpMethod.POST,
            new HttpEntity<>(requestBody, headers), new ParameterizedTypeReference<Void>() {});
        return response;
    }
}
