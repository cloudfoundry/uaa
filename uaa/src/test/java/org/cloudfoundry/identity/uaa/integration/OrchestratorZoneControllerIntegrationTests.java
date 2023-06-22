package org.cloudfoundry.identity.uaa.integration;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.assertSupportsZoneDNS;
import static org.cloudfoundry.identity.uaa.mock.zones.OrchestratorZoneControllerMockMvcTests.DASHBOARD_URI;
import static org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService.DASHBOARD_LOGIN_PATH;
import static org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService.X_IDENTITY_ZONE_ID;
import static org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService.ZONE_CREATED_MESSAGE;
import static org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService.ZONE_DELETED_MESSAGE;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.OrchestratorState;
import org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm;
import org.cloudfoundry.identity.uaa.zone.model.ConnectionDetails;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneHeader;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.hamcrest.MatcherAssert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@OAuth2ContextConfiguration(OrchestratorZoneControllerIntegrationTests.OrchestratorClient.class)
public class OrchestratorZoneControllerIntegrationTests {

    private static final Logger LOGGER = LoggerFactory.getLogger(OrchestratorZoneControllerIntegrationTests.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String OAUTH_CLIENT_ENDPOINT = "/oauth/clients";
    private static final String CHECK_TOKEN_ENDPOINT = "/check_token";
    private static final String TOKEN_KEY_ENDPOINT = "/token_key";
    private static final String IDENTITY_PROVIDERS_ENDPOINT = "/identity-providers";
    private static final String ORCHESTRATOR_ZONES_APIS_ENDPOINT = "/orchestrator/zones";
    private static final String NATIVE_ZONES_APIS_ENDPOINT = "/identity-zones";
    private static final String ORCHESTRATOR_INT_TEST_ZONE = "orchestrator-int-test-zone";
    private static final String ZONE_SUBDOMAIN = "sub-domain-01";
    private static final String ADMIN_CLIENT_SECRET = "admin-secret-01";
    private static final String SUPER_ADMIN_CLIENT_SECRET = "adminsecret";
    private static final String ADMIN_CLIENT_NAME = "admin";

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
            serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT) + "?name=" + zoneName,
            OrchestratorZoneResponse.class);

        if (response.getStatusCode().is2xxSuccessful()) {
            OrchestratorZoneHeader expectedZoneHeader = new OrchestratorZoneHeader();
            expectedZoneHeader.setHttpHeaderName(X_IDENTITY_ZONE_ID);
            expectedZoneHeader.setHttpHeaderValue(zoneName);

            ConnectionDetails expectedConnectionDetails = new ConnectionDetails();
            expectedConnectionDetails.setSubdomain(zoneName);
            expectedConnectionDetails.setZone(expectedZoneHeader);
            expectedConnectionDetails.setUri("http://" + zoneName + ".localhost:8080/uaa");
            expectedConnectionDetails.setIssuerId("http://" + zoneName + ".localhost:8080/uaa/oauth/token");

            OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
            expectedResponse.setName(zoneName);
            expectedResponse.setConnectionDetails(expectedConnectionDetails);
            expectedResponse.setMessage("");
            expectedResponse.setState(OrchestratorState.FOUND.toString());

            assertResponse(expectedResponse, response.getBody());
        } else {
            fail("Server not returning expected status code");
        }
    }

    private void assertResponse(OrchestratorZoneResponse expectedResponse, OrchestratorZoneResponse actualResponse) {
        assertNotNull(actualResponse);
        assertNull(actualResponse.getParameters());
        assertNotNull(actualResponse.getState());
        assertEquals(expectedResponse.getState(), actualResponse.getState());

        if (expectedResponse.getName() != null ) {
            assertNotNull(actualResponse.getName());
        }
        assertEquals(expectedResponse.getName(), actualResponse.getName());

        ConnectionDetails expectedConnectionDetails = expectedResponse.getConnectionDetails();
        ConnectionDetails actualConnectionDetails = actualResponse.getConnectionDetails();
        if (expectedConnectionDetails == null) {
            assertNull(actualConnectionDetails);
        } else {
            assertNotNull(actualConnectionDetails);
            assertEquals(expectedConnectionDetails.getSubdomain(), actualConnectionDetails.getSubdomain());
            assertEquals(expectedConnectionDetails.getUri(), actualConnectionDetails.getUri());
            MatcherAssert.assertThat(actualConnectionDetails.getDashboardUri(), containsString(
                DASHBOARD_URI + DASHBOARD_LOGIN_PATH));
            assertEquals(expectedConnectionDetails.getIssuerId(), actualConnectionDetails.getIssuerId());
            assertEquals(expectedConnectionDetails.getZone().getHttpHeaderName(),
                    actualConnectionDetails.getZone().getHttpHeaderName());
            assertNotNull(actualConnectionDetails.getZone().getHttpHeaderValue());
        }

        assertNotNull(actualResponse.getMessage());
        if (expectedResponse.getMessage().isEmpty()) {
            assertTrue(actualResponse.getMessage().isEmpty());
        } else {
            assertEquals(expectedResponse.getMessage(), actualResponse.getMessage());
        }
    }

    @Test
    public void testGetZone_NotFound() {
        ResponseEntity<OrchestratorZoneResponse> response = client.getForEntity(
            serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT) + "?name=random-name",
                OrchestratorZoneResponse.class);
        if (response.getStatusCode().is4xxClientError()) {
            assertEquals(response.getStatusCode(), HttpStatus.NOT_FOUND);

            OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
            expectedResponse.setName("random-name");
            expectedResponse.setMessage("Zone[random-name] not found.");
            expectedResponse.setState(OrchestratorState.NOT_FOUND.toString());

            assertResponse(expectedResponse, response.getBody());
        } else {
            fail("Server not returning expected status code");
        }
    }

    @Test
    public void testGetZone_EmptyError() {
        ResponseEntity<OrchestratorZoneResponse> response = client.getForEntity(
            serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT),
                OrchestratorZoneResponse.class);

        if (response.getStatusCode().is4xxClientError()) {
            assertEquals(response.getStatusCode(), HttpStatus.BAD_REQUEST);
            assertEquals(APPLICATION_JSON_UTF8, response.getHeaders().getContentType());

            OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
            expectedResponse.setMessage("Required request parameter 'name' for method parameter type String is not present");
            expectedResponse.setState(OrchestratorState.PERMANENT_FAILURE.toString());

            assertResponse(expectedResponse, response.getBody());
        } else {
            fail("Server not returning expected status code");
        }
    }

    @Test
    public void testGetZone_NameRequiredError() {
        ResponseEntity<OrchestratorZoneResponse> response = client.getForEntity(
            serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT) + "?name=",
                OrchestratorZoneResponse.class);
        if (response.getStatusCode().is4xxClientError()) {
            assertEquals(response.getStatusCode(), HttpStatus.BAD_REQUEST);
            assertEquals(APPLICATION_JSON_UTF8, response.getHeaders().getContentType());

            OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
            expectedResponse.setMessage("name must be specified");
            expectedResponse.setState(OrchestratorState.PERMANENT_FAILURE.toString());

            assertResponse(expectedResponse, response.getBody());
        } else {
            fail("Server not returning expected status code");
        }
    }

    @Test
    public void testDeleteZone() {
        String zoneName = createZoneGetZoneName();

        ResponseEntity<OrchestratorZoneResponse> response =
            client.exchange(serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT) + "?name=" + zoneName,
                            HttpMethod.DELETE, null, OrchestratorZoneResponse.class);

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());

        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName(zoneName);
        expectedResponse.setMessage(ZONE_DELETED_MESSAGE);
        expectedResponse.setState(OrchestratorState.DELETE_IN_PROGRESS.toString());

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertResponse(expectedResponse, response.getBody());

        ResponseEntity<OrchestratorZoneResponse> getResponse = client.getForEntity(
            serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT) + "?name=" + zoneName,
                OrchestratorZoneResponse.class);
        assertEquals(getResponse.getStatusCode(), HttpStatus.NOT_FOUND);
    }

    @Test
    public void testDeleteZone_NotFound() {
        ResponseEntity<OrchestratorZoneResponse> response =
            client.exchange(serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT) + "?name=random-name",
                            HttpMethod.DELETE, null, OrchestratorZoneResponse.class);

        assertEquals(response.getStatusCode(), HttpStatus.NOT_FOUND);

        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName("random-name");
        expectedResponse.setMessage("Zone[random-name] not found.");
        expectedResponse.setState(OrchestratorState.NOT_FOUND.toString());

        assertResponse(expectedResponse, response.getBody());
    }

    @Test
    public void testDeleteZone_NameRequiredError() {
        ResponseEntity<OrchestratorZoneResponse> response =
            client.exchange(serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT) + "?name=",
                            HttpMethod.DELETE, null, OrchestratorZoneResponse.class);

        if (response.getStatusCode().is4xxClientError()) {
            assertEquals(response.getStatusCode(), HttpStatus.BAD_REQUEST);
            assertEquals(APPLICATION_JSON_UTF8, response.getHeaders().getContentType());

            OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
            expectedResponse.setMessage("name must be specified");
            expectedResponse.setState(OrchestratorState.PERMANENT_FAILURE.toString());

            assertResponse(expectedResponse, response.getBody());
        } else {
            fail("Server not returning expected status code");
        }
    }

    @Test
    public void testUpdateZone() {
        OrchestratorZoneRequest zoneRequest = new OrchestratorZoneRequest();
        zoneRequest.setName("test name");
        zoneRequest.setParameters(new OrchestratorZone(ADMIN_CLIENT_SECRET, null));

        ResponseEntity<OrchestratorZoneResponse> getResponse = client.exchange(
            serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT), HttpMethod.PUT, new HttpEntity<>(zoneRequest),
                OrchestratorZoneResponse.class);

        assertEquals(getResponse.getStatusCode(), HttpStatus.METHOD_NOT_ALLOWED);

        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setMessage("Put Operation not Supported");
        expectedResponse.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        assertResponse(expectedResponse, getResponse.getBody());
    }

    @Test
    public void testCreateZone() {
        String zoneName = getName();
        ResponseEntity<OrchestratorZoneResponse> response = createZone(zoneName);

        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName(zoneName);
        expectedResponse.setMessage(ZONE_CREATED_MESSAGE);
        expectedResponse.setState(OrchestratorState.CREATE_IN_PROGRESS.toString());

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertResponse(expectedResponse, response.getBody());
    }

    @Test
    public void testCreateZone_WithZoneConfigValidation() throws Throwable {
        assertSupportsZoneDNS();

        // Create zone using orchestrator zone api
        String zoneName = ORCHESTRATOR_INT_TEST_ZONE;
        ResponseEntity<OrchestratorZoneResponse> postResponse = createZone(zoneName);
        assertEquals(HttpStatus.ACCEPTED, postResponse.getStatusCode());

        // Fetch orchestrator created zone to get auto generated id of zone
        ResponseEntity<OrchestratorZoneResponse> getResponse = client.getForEntity(
            serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT) + "?name=" + zoneName,
            OrchestratorZoneResponse.class);
        OrchestratorZoneResponse getZoneResponse = getResponse.getBody();
        final String subdomain= zoneName;
        final String zoneId = getZoneResponse.getConnectionDetails().getZone().getHttpHeaderValue();
        final String zoneUri = getZoneResponse.getConnectionDetails().getUri();

        // Create rest template using base uaa admin client
        OAuth2RestTemplate adminClient = (OAuth2RestTemplate) IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(), new String[0],
                        ADMIN_CLIENT_NAME, SUPER_ADMIN_CLIENT_SECRET));

        OAuth2RestTemplate zoneAdminClient = (OAuth2RestTemplate) IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(zoneUri, new String[0],
                        ADMIN_CLIENT_NAME, ADMIN_CLIENT_SECRET));

        // Validate zone config (Validation steps extracted from Service Broker IT Tests)
        validateZoneConfiguration(zoneId, adminClient);
        validateZoneAdminClient(zoneUri, zoneId, zoneAdminClient);
        validateZoneDefaultIdentityProvider(zoneUri, zoneId, zoneAdminClient);
        validateZoneTokenKeyEndpoint(zoneUri);
        validateZoneCheckTokenEndpoint(zoneUri);

        // Delete zone using orchestrator zone api as it was created with orchestrator zone api
        // and having foreign key ref in `orchestrator_zone` table
        ResponseEntity<Void> response = client.exchange(
                serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT + "?name=" + zoneName), HttpMethod.DELETE,
                HttpEntity.EMPTY, Void.class);
        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());

        // Validate zone is deleted by calling native get zone api and should return 404
        response = adminClient.getForEntity(
                serverRunning.getUrl(NATIVE_ZONES_APIS_ENDPOINT + "/" + zoneId), Void.class);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    public void testCreateZone_Duplicate_Subdomain_Returns_409_Conflict() {
        String subDomain = createZoneGetZoneName();
        String name = getName();
        String requestBody = JsonUtils.writeValueAsString(getOrchestratorZoneRequest(name, ADMIN_CLIENT_SECRET, subDomain));
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        ResponseEntity<OrchestratorZoneResponse> response = client.exchange(
            serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT),
            HttpMethod.POST,
            new HttpEntity<>(requestBody, headers),OrchestratorZoneResponse.class);

        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName(name);
        expectedResponse.setMessage(
                String.format("The subdomain name %s is already taken. Please use a different subdomain",
                subDomain));
        expectedResponse.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertResponse(expectedResponse, response.getBody());
    }

    @Test
    public void testCreateAndGetZone_SubdomainAsNULL_inRequestBody() {
        String zoneName = createZoneSubdomainAsNullInParameter();

        ResponseEntity<OrchestratorZoneResponse> getResponse = client.getForEntity(
            serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT) + "?name=" + zoneName,
            OrchestratorZoneResponse.class);
        if (getResponse.getStatusCode().is2xxSuccessful()) {
            OrchestratorZoneResponse zoneResponse = getResponse.getBody();
            assertNotNull(zoneResponse);
            String connectionDetailSubdomain = zoneResponse.getConnectionDetails().getSubdomain();
            assertNotNull(connectionDetailSubdomain);
            String uri = "http://" + connectionDetailSubdomain + ".localhost:8080/uaa";
            assertEquals(uri, zoneResponse.getConnectionDetails().getUri());
            MatcherAssert.assertThat(zoneResponse.getConnectionDetails().getDashboardUri(), containsString(
                DASHBOARD_URI + DASHBOARD_LOGIN_PATH));
            assertEquals(uri + "/oauth/token", zoneResponse.getConnectionDetails().getIssuerId());
            assertEquals(X_IDENTITY_ZONE_ID, zoneResponse.getConnectionDetails().getZone().getHttpHeaderName());
            assertEquals(connectionDetailSubdomain, zoneResponse.getConnectionDetails().getZone().getHttpHeaderValue());
        } else {
            fail("Server not returning expected status code");
        }
    }

    private String createZoneSubdomainAsNullInParameter() {
        String zoneName = getName();
        String requestBody = JsonUtils.writeValueAsString(getOrchestratorZoneRequest(zoneName, ADMIN_CLIENT_SECRET,
                                                                                     null));
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        ResponseEntity<OrchestratorZoneResponse> response = client.exchange(
            serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT),
            HttpMethod.POST,
            new HttpEntity<>(requestBody, headers), OrchestratorZoneResponse.class);


        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName(zoneName);
        expectedResponse.setMessage(ZONE_CREATED_MESSAGE);
        expectedResponse.setState(OrchestratorState.CREATE_IN_PROGRESS.toString());

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        assertResponse(expectedResponse, response.getBody());
        return zoneName;
    }

    @Test
    public void testCreateZone_ZoneAlreadyExists() {
        String zoneName = createZoneGetZoneName();
        OrchestratorZoneRequest orchestratorZoneRequest = getOrchestratorZoneRequest(zoneName, ADMIN_CLIENT_SECRET,
                ZONE_SUBDOMAIN);
        ResponseEntity<OrchestratorZoneResponse> getResponseAlreadyExist = client.exchange(
                serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT),
                HttpMethod.POST,
                new HttpEntity<>(orchestratorZoneRequest),
                OrchestratorZoneResponse.class);

        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName(zoneName);
        expectedResponse.setMessage(
                String.format("The zone name %s is already taken. Please use a different zone name",
                        orchestratorZoneRequest.getName()));
        expectedResponse.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        assertEquals(HttpStatus.CONFLICT, getResponseAlreadyExist.getStatusCode());
        assertResponse(expectedResponse, getResponseAlreadyExist.getBody());
    }

    @Test
    public void testCreateZone_nameAsSpaceAndEmptyError() {
        testNameAsSpaceAndEmpty(getOrchestratorZoneRequest("", ADMIN_CLIENT_SECRET, ZONE_SUBDOMAIN));
        testNameAsSpaceAndEmpty(getOrchestratorZoneRequest("    ", ADMIN_CLIENT_SECRET, ZONE_SUBDOMAIN));
    }

    @Test
    public void testCreateZone_subDomainWithSpaceOrSpecialCharFail() {
        testWithSpaceOrSpecialCharFail(getOrchestratorZoneRequest(getName(), ADMIN_CLIENT_SECRET,
                                                                  "  "));
        testWithSpaceOrSpecialCharFail(getOrchestratorZoneRequest(getName(), ADMIN_CLIENT_SECRET,
                                                                  "sub    domain"));
        testWithSpaceOrSpecialCharFail(getOrchestratorZoneRequest(getName(), ADMIN_CLIENT_SECRET,
                                                                  "sub#-domain"));
        testWithSpaceOrSpecialCharFail(getOrchestratorZoneRequest(getName(), ADMIN_CLIENT_SECRET,
                                                                  "-subdomainStartsWithHYphen"));
        testWithSpaceOrSpecialCharFail(getOrchestratorZoneRequest(getName(), ADMIN_CLIENT_SECRET,
                                                                  "subdomainEndsWithHYphen-"));
        testWithSpaceOrSpecialCharFail(getOrchestratorZoneRequest(getName(), ADMIN_CLIENT_SECRET,
                                                                  "sub\\\\domaincontainsslash"));
        testWithSpaceOrSpecialCharFail(getOrchestratorZoneRequest(getName(), ADMIN_CLIENT_SECRET,
                                                                  "sub$%domaincontainsSpecialChars"));
    }

    @Test
    public void testCreateZone_adminClientSecretAsSpaceAndEmptyError() {
        testAdminClientSecretAsSpaceAndEmpty(getOrchestratorZoneRequest(getName(),"", ZONE_SUBDOMAIN));
        testAdminClientSecretAsSpaceAndEmpty(getOrchestratorZoneRequest(getName(),"    ", ZONE_SUBDOMAIN));
    }

    private void testAdminClientSecretAsSpaceAndEmpty(OrchestratorZoneRequest orchestratorZoneRequest) {
        ResponseEntity<OrchestratorZoneResponse> getResponse = client.exchange(
                serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT), HttpMethod.POST,
                new HttpEntity<>(orchestratorZoneRequest), OrchestratorZoneResponse.class);

        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName(orchestratorZoneRequest.getName());
        expectedResponse.setMessage("parameters.adminClientSecret must not be empty and must not have empty spaces");
        expectedResponse.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        assertEquals(getResponse.getStatusCode(), HttpStatus.BAD_REQUEST);
        assertEquals(APPLICATION_JSON_UTF8, getResponse.getHeaders().getContentType());
        assertResponse(expectedResponse, getResponse.getBody());
    }

    private void testWithSpaceOrSpecialCharFail(OrchestratorZoneRequest orchestratorZoneRequest) {
        ResponseEntity<OrchestratorZoneResponse> getResponse = client.exchange(
                serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT), HttpMethod.POST,
                new HttpEntity<>(orchestratorZoneRequest), OrchestratorZoneResponse.class);

        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName(orchestratorZoneRequest.getName());
        expectedResponse.setMessage("parameters.subdomain is invalid. Special characters are not allowed in the " +
                "subdomain name except hyphen which can be specified in the middle");
        expectedResponse.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        assertEquals(getResponse.getStatusCode(), HttpStatus.BAD_REQUEST);
        assertEquals(APPLICATION_JSON_UTF8, getResponse.getHeaders().getContentType());
        assertResponse(expectedResponse, getResponse.getBody());
    }

    private void testNameAsSpaceAndEmpty(OrchestratorZoneRequest orchestratorZoneRequest) {
        ResponseEntity<OrchestratorZoneResponse> getResponse = client.exchange(
            serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT), HttpMethod.POST,
                new HttpEntity<>(orchestratorZoneRequest), OrchestratorZoneResponse.class);

        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName(orchestratorZoneRequest.getName());
        expectedResponse.setMessage("name must not be blank");
        expectedResponse.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        assertEquals(getResponse.getStatusCode(), HttpStatus.BAD_REQUEST);
        assertEquals(APPLICATION_JSON_UTF8, getResponse.getHeaders().getContentType());
        assertResponse(expectedResponse, getResponse.getBody());
    }

    static class OrchestratorClient extends ClientCredentialsResourceDetails {

        public OrchestratorClient(Object target) {
            OrchestratorZoneControllerIntegrationTests test = (OrchestratorZoneControllerIntegrationTests) target;
            ClientCredentialsResourceDetails resource = test.testAccounts.getClientCredentialsResource(
                    new String[] {"uaa.none"}, "orchestrator-zone-provisioner", "orchestratorsecret");
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
        return UUID.randomUUID().toString();
    }

    private String createZoneGetZoneName() {
        String zoneName = getName();
        ResponseEntity<OrchestratorZoneResponse> createZoneResponse = createZone(zoneName);
        assertEquals(HttpStatus.ACCEPTED, createZoneResponse.getStatusCode());
        return zoneName;
    }

    private ResponseEntity<OrchestratorZoneResponse> createZone(String zoneName) {
        String subDomain =  zoneName;
        String requestBody = JsonUtils.writeValueAsString(getOrchestratorZoneRequest(zoneName, ADMIN_CLIENT_SECRET, subDomain));
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        ResponseEntity<OrchestratorZoneResponse> response = client.postForEntity(
            serverRunning.getUrl(ORCHESTRATOR_ZONES_APIS_ENDPOINT),
            new HttpEntity<>(requestBody, headers), OrchestratorZoneResponse.class);

        return response;
    }

    private void validateZoneConfiguration(final String zoneId, final OAuth2RestTemplate adminClient)
        throws Exception {

        // Get zone config and check
        ResponseEntity<IdentityZone> identityZoneResponse = adminClient.getForEntity(
                serverRunning.getUrl(NATIVE_ZONES_APIS_ENDPOINT + "/" + zoneId), IdentityZone.class);
        LOGGER.info("Got identity zone: " + OBJECT_MAPPER.writeValueAsString(identityZoneResponse.getBody()));

        IdentityZoneConfiguration config = identityZoneResponse.getBody().getConfig();
        assertEquals(config.getLinks().getLogout().getWhitelist(),Collections.singletonList("http*://**"));
        assertFalse(config.getLinks().getSelfService().isSelfServiceCreateAccountEnabled());
        Assertions.assertTrue(config.getLinks().getSelfService().isSelfServiceResetPasswordEnabled());
        assertEquals(config.getLinks().getSelfService().getSignup(), "");
        assertEquals(config.getLinks().getSelfService().getPasswd(), "/forgot_password");
        assertFalse(config.isIdpDiscoveryEnabled());
        assertNotNull(config.getTokenPolicy().getActiveKeyId());

        checkSamlConfig(config.getSamlConfig());
        checkSamlCert(identityZoneResponse.getBody().getSubdomain(),
                      config.getSamlConfig().getKeys().get(config.getSamlConfig().getActiveKeyId()));
    }

    private void checkSamlConfig(final SamlConfig samlConfig) {
        assertNotNull(samlConfig.getSignatureAlgorithm());
        assertEquals(samlConfig.getSignatureAlgorithm(), SignatureAlgorithm.SHA256);
        assertNotNull(samlConfig.getActiveKeyId());
    }

    private void checkSamlCert(String subdomain, SamlKey samlKey) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) factory.generateCertificate(
            new ByteArrayInputStream(samlKey.getCertificate().getBytes()));
        assertThat(cert.getSubjectDN().getName(), containsString("PredixUAA" + subdomain));
    }

    private void validateZoneCheckTokenEndpoint(final String zoneUri) {
        String accessToken = IntegrationTestUtils.getClientCredentialsToken(
                zoneUri, ADMIN_CLIENT_NAME, ADMIN_CLIENT_SECRET);

        MultiValueMap<String, String> request = new LinkedMultiValueMap<>();
        request.add("token", accessToken);
        request.add("grant_type", "client_credentials");

        RestTemplate template = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Basic " + new String(
                Base64.encode(String.format("%s:%s", ADMIN_CLIENT_NAME, ADMIN_CLIENT_SECRET).getBytes())));

        ResponseEntity<Map> responseEntity = template.exchange(
                zoneUri + CHECK_TOKEN_ENDPOINT,
                HttpMethod.POST,
                new HttpEntity<>(request, headers),
                Map.class);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        String clientId = String.valueOf(responseEntity.getBody().get("client_id"));
        assertEquals(clientId, ADMIN_CLIENT_NAME);
    }

    private void validateZoneAdminClient(final String zoneUri,
                                         final String zoneId,
                                         final OAuth2RestTemplate zoneAdminClient) {

        ResponseEntity<BaseClientDetails> baseClientDetailsResponse = zoneAdminClient.getForEntity(
                zoneUri + OAUTH_CLIENT_ENDPOINT + "/admin",
                BaseClientDetails.class);
        BaseClientDetails baseClientDetails = baseClientDetailsResponse.getBody();

        Collection<GrantedAuthority> authorities = baseClientDetails.getAuthorities();
        List<String> defaultAuthList =
            new ArrayList<>(Arrays.asList(OrchestratorZoneService.ZONE_AUTHORITIES.split(",")));
        defaultAuthList.add("zones." + zoneId + ".admin");
        for (GrantedAuthority authority : authorities) {
            LOGGER.info("Retrieved authority: " + authority.getAuthority());
            assertTrue(defaultAuthList.contains(authority.getAuthority()));
        }
    }

    private void validateZoneDefaultIdentityProvider(final String zoneUri,
                                                     final String zoneId,
                                                     final OAuth2RestTemplate zoneAdminClient) {

        ResponseEntity<List<IdentityProvider>> idpList = zoneAdminClient.exchange(
                zoneUri + IDENTITY_PROVIDERS_ENDPOINT,
                HttpMethod.GET,
                HttpEntity.EMPTY,
                new ParameterizedTypeReference<List<IdentityProvider>>() {});

        assertTrue(idpList.getHeaders().getContentType().includes(MediaType.APPLICATION_JSON_UTF8));

        IdentityProvider identityProvider = idpList.getBody().get(0);
        assertThat(identityProvider.getIdentityZoneId(), is(zoneId));
        assertThat(identityProvider.getOriginKey(), is(OriginKeys.UAA));

        // The default created zone does have a definition, but no policy
        UaaIdentityProviderDefinition identityProviderDefinition =
                (UaaIdentityProviderDefinition) identityProvider.getConfig();
        assertNotNull(identityProviderDefinition);
        assertNull(identityProviderDefinition.getPasswordPolicy());
    }

    private void validateZoneTokenKeyEndpoint(final String zoneUri) {
        //Make sure that token key is valid and able to retrieve
        ResponseEntity<String> response =
                new RestTemplate().getForEntity(zoneUri + TOKEN_KEY_ENDPOINT, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
    }
}
