package org.cloudfoundry.identity.uaa.mock.zones;

import static org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService.X_IDENTITY_ZONE_ID;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.stream.Stream;

import net.bytebuddy.utility.RandomString;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.OrchestratorState;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneModifiedEvent;
import org.cloudfoundry.identity.uaa.zone.model.ConnectionDetails;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorErrorResponse;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneHeader;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;

@DefaultTestContext
public class OrchestratorZoneControllerMockMvcTests {

    public static final String ZONE_NAME = "The Twiglet Zone";
    public static final String SUB_DOMAIN_NAME = "sub-domain-01";
    public static final String ADMIN_CLIENT_SECRET = "admin-secret-01";

    private MockMvc mockMvc;
    private String orchestratorZonesReadToken = null;
    private String orchestratorZonesWriteToken = null;
    private TestApplicationEventListener<AbstractUaaEvent> uaaEventListener;
    private TestApplicationEventListener<IdentityZoneModifiedEvent> zoneModifiedEventListener;

    private final String serviceProviderKey =
        "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIICXQIBAAKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5\n" +
        "L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vA\n" +
        "fpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQAB\n" +
        "AoGAVOj2Yvuigi6wJD99AO2fgF64sYCm/BKkX3dFEw0vxTPIh58kiRP554Xt5ges\n" +
        "7ZCqL9QpqrChUikO4kJ+nB8Uq2AvaZHbpCEUmbip06IlgdA440o0r0CPo1mgNxGu\n" +
        "lhiWRN43Lruzfh9qKPhleg2dvyFGQxy5Gk6KW/t8IS4x4r0CQQD/dceBA+Ndj3Xp\n" +
        "ubHfxqNz4GTOxndc/AXAowPGpge2zpgIc7f50t8OHhG6XhsfJ0wyQEEvodDhZPYX\n" +
        "kKBnXNHzAkEAyCA76vAwuxqAd3MObhiebniAU3SnPf2u4fdL1EOm92dyFs1JxyyL\n" +
        "gu/DsjPjx6tRtn4YAalxCzmAMXFSb1qHfwJBAM3qx3z0gGKbUEWtPHcP7BNsrnWK\n" +
        "vw6By7VC8bk/ffpaP2yYspS66Le9fzbFwoDzMVVUO/dELVZyBnhqSRHoXQcCQQCe\n" +
        "A2WL8S5o7Vn19rC0GVgu3ZJlUrwiZEVLQdlrticFPXaFrn3Md82ICww3jmURaKHS\n" +
        "N+l4lnMda79eSp3OMmq9AkA0p79BvYsLshUJJnvbk76pCjR28PK4dV1gSDUEqQMB\n" +
        "qy45ptdwJLqLJCeNoR0JUcDNIRhOCuOPND7pcMtX6hI/\n" +
        "-----END RSA PRIVATE KEY-----";

    private final String serviceProviderKeyPassword = "password";

    private final String serviceProviderCertificate =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEO\n" +
        "MAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEO\n" +
        "MAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5h\n" +
        "cnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwx\n" +
        "CzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAM\n" +
        "BgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAb\n" +
        "BgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GN\n" +
        "ADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39W\n" +
        "qS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOw\n" +
        "znoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4Ha\n" +
        "MIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGc\n" +
        "gBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYD\n" +
        "VQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYD\n" +
        "VQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJh\n" +
        "QGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ\n" +
        "0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxC\n" +
        "KdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkK\n" +
        "RpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n" +
        "-----END CERTIFICATE-----\n";

    @BeforeEach
    void setUp(@Autowired MockMvc mockMvc,
               @Autowired TestClient testClient, @Autowired ClientRegistrationService clientRegistrationService,
               @Autowired
               ConfigurableApplicationContext configurableApplicationContext)
        throws Exception {
        this.mockMvc = mockMvc;
        zoneModifiedEventListener =
            MockMvcUtils.addEventListener(configurableApplicationContext, IdentityZoneModifiedEvent.class);
        uaaEventListener = MockMvcUtils.addEventListener(configurableApplicationContext, AbstractUaaEvent.class);

        orchestratorZonesReadToken = getAccessToken(
                clientRegistrationService,
                testClient,
                "orchestrator-zone-reader-" + RandomString.make(5).toLowerCase(),
                "r3ader",
                "orchestrator.zones.read");
        orchestratorZonesWriteToken = getAccessToken(
                clientRegistrationService,
                testClient,
                "orchestrator-zone-provisioner-" + RandomString.make(5).toLowerCase(),
            "pr0visioner",
            "orchestrator.zones.read,orchestrator.zones.write");
    }

    private String getAccessToken(ClientRegistrationService clientRegistrationService,
                                  TestClient testClient,
                                  String clientId,
                                  String clientSecret,
                                  String scope) throws Exception {
        BaseClientDetails clientDetails = new BaseClientDetails(
                clientId,
                null,
                "uaa.none",
                "client_credentials",
                scope);
        clientDetails.setClientSecret(clientSecret);
        clientRegistrationService.addClientDetails(clientDetails);
        return testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret, scope);
    }

    @ParameterizedTest
    @ArgumentsSource(IdentityZonesBaseUrlsArgumentsSource.class)
    void testGetZone_Unauthorized(String url) throws Exception {
        mockMvc.perform(get(url))
               .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ArgumentsSource(NameRequiredArgumentsSource.class)
    void testGetZone_nameRequiredError(String url) throws Exception {
        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse(null, null,
                "Required request parameter 'name' for method parameter type String is not present",
                OrchestratorState.PERMANENT_FAILURE.toString());

        performMockMvcCallAndAssertResponse(get(url), orchestratorZonesReadToken, status().isBadRequest(),
                expectedResponse);
    }

    @ParameterizedTest
    @ArgumentsSource(NameNotEmptyArgumentsSource.class)
    void testGetZone_nameEmptyError(String url) throws Exception {
        performMockMvcCallAndAssertError(get(url), status().isBadRequest(),
                                         JsonUtils.writeValueAsString(
                                             new OrchestratorErrorResponse("name must be specified")),
                orchestratorZonesReadToken);
    }

    @Test
    void testGetZone() throws Exception {
        createOrchestratorZoneAndAssert();

        OrchestratorZoneHeader expectedZoneHeader = new OrchestratorZoneHeader();
        expectedZoneHeader.setHttpHeaderName(X_IDENTITY_ZONE_ID);
        expectedZoneHeader.setHttpHeaderValue(SUB_DOMAIN_NAME);

        ConnectionDetails expectedConnectionDetails = new ConnectionDetails();
        expectedConnectionDetails.setSubdomain(SUB_DOMAIN_NAME);
        expectedConnectionDetails.setUri("http://" + SUB_DOMAIN_NAME + ".localhost");
        expectedConnectionDetails.setDashboardUri("http://localhost:8080/dashboard");
        expectedConnectionDetails.setIssuerId(expectedConnectionDetails.getUri() + "/oauth/token");
        expectedConnectionDetails.setZone(expectedZoneHeader);

        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName(ZONE_NAME);
        expectedResponse.setConnectionDetails(expectedConnectionDetails);
        expectedResponse.setMessage("");
        expectedResponse.setState(OrchestratorState.FOUND.toString());

        performMockMvcCallAndAssertResponse(get("/orchestrator/zones").param("name", ZONE_NAME), orchestratorZonesReadToken,
                status().isOk(), expectedResponse);

        // deleting after create and get to avoid multiple value in the database
        performMockMvcCall(delete("/orchestrator/zones"), ZONE_NAME, orchestratorZonesWriteToken,
                status().isAccepted());
    }

    private OrchestratorZoneResponse performMockMvcCall(MockHttpServletRequestBuilder mockRequestBuilder,
                                                        String nameParameter,
                                                        String token,
                                                        ResultMatcher expectedStatus) throws Exception {
        MvcResult result = mockMvc.perform(mockRequestBuilder.param("name", nameParameter)
                        .header("Authorization", "Bearer " + token)).andExpect(expectedStatus).andReturn();
        if (StringUtils.hasLength(result.getResponse().getContentAsString())) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), OrchestratorZoneResponse.class);
        } else {
            return null;
        }
    }

    private void performMockMvcCallAndAssertResponse(MockHttpServletRequestBuilder mockRequestBuilder,
                                                     String token,
                                                     ResultMatcher expectedStatus,
                                                     OrchestratorZoneResponse expectedResponse) throws Exception {

        MvcResult result = mockMvc.perform(mockRequestBuilder.header("Authorization", "Bearer " + token))
                .andExpect(expectedStatus).andReturn();

        assertNotNull(result);
        assertNotNull(result.getResponse());
        assertTrue(StringUtils.hasLength(result.getResponse().getContentAsString()));
        assertEquals(APPLICATION_JSON_VALUE, result.getResponse().getContentType());

        OrchestratorZoneResponse actualResponse =
                JsonUtils.readValue(result.getResponse().getContentAsString(), OrchestratorZoneResponse.class);

        assertNotNull(actualResponse);
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
            assertEquals(expectedConnectionDetails.getDashboardUri(), actualConnectionDetails.getDashboardUri());
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

    private void performMockMvcCallAndAssertError(MockHttpServletRequestBuilder identityZone,
                                                  ResultMatcher expectedStatus,
                                                  String expected, String token) throws Exception {
        MvcResult result = mockMvc.perform(identityZone
                                               .header("Authorization", "Bearer " + token))
                                  .andExpect(expectedStatus).andReturn();
        assertEquals(expected, result.getResponse().getContentAsString());
        assertEquals(APPLICATION_JSON_VALUE, result.getResponse().getContentType());
    }

    @Test
    void testGetZone_NotFound() throws Exception {
        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName("random-name");
        expectedResponse.setMessage("Zone[random-name] not found.");
        expectedResponse.setState(OrchestratorState.NOT_FOUND.toString());

        performMockMvcCallAndAssertResponse(get("/orchestrator/zones").param("name", "random-name"),
                orchestratorZonesReadToken, status().isNotFound(), expectedResponse);
    }

    @Test
    void testDeleteZone() throws Exception {
        createOrchestratorZoneAndAssert();
        uaaEventListener.clearEvents();

        performMockMvcCall(delete("/orchestrator/zones"), ZONE_NAME, orchestratorZonesWriteToken, status().isAccepted());

        // Asserting that zone got deleted
        performMockMvcCall(get("/orchestrator/zones"), ZONE_NAME, orchestratorZonesWriteToken, status().isNotFound());

        // Asserting delete event
        assertThat(uaaEventListener.getEventCount(), is(1));
        AbstractUaaEvent event = uaaEventListener.getLatestEvent();
        assertThat(event, instanceOf(EntityDeletedEvent.class));
        EntityDeletedEvent deletedEvent = (EntityDeletedEvent) event;
        assertThat(deletedEvent.getDeleted(), instanceOf(IdentityZone.class));
    }

    @Test
    void testDeleteZone_NotFound() throws Exception {
        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName("random-name");
        expectedResponse.setMessage("Zone[random-name] not found.");
        expectedResponse.setState(OrchestratorState.NOT_FOUND.toString());

        performMockMvcCallAndAssertResponse(delete("/orchestrator/zones").param("name", "random-name"),
                orchestratorZonesWriteToken, status().isNotFound(), expectedResponse);
    }

    @Test
    void testDeleteZone_Forbidden() throws Exception {
        performMockMvcCallAndAssertError(delete("/orchestrator/zones").param("name", "random-name"),
                                         status().isForbidden(),
                                         "{\"error\":\"insufficient_scope\",\"error_description\":\"Insufficient " +
                                         "scope for this resource\",\"scope\":\"uaa.admin orchestrator.zones.write zones.uaa.admin zones" +
                                         ".write\"}",
                orchestratorZonesReadToken);
    }

    @Test
    void testUpdateZone_MethodNotImplemented() throws Exception {
        performMockMvcCallAndAssertError(put("/orchestrator/zones").contentType(APPLICATION_JSON).content(
                                             "{\"name\": \"\",\"parameters\": {\"adminSecret\": \"\",\"subDomain\": \"\"}}"),
                                         status().isMethodNotAllowed(),
                                         JsonUtils.writeValueAsString(
                                             new OrchestratorErrorResponse("Put Operation not Supported")),
                orchestratorZonesWriteToken);
    }

    @Test
    void testUpdateZone_Forbidden() throws Exception {
        performMockMvcCallAndAssertError(put("/orchestrator/zones").contentType(APPLICATION_JSON).content(
                                             "{\"name\": \"\",\"parameters\": {\"adminSecret\": \"\",\"subDomain\": \"\"}}"),
                                         status().isForbidden(),
                                         "{\"error\":\"insufficient_scope\",\"error_description\":\"Insufficient " +
                                         "scope for this resource\",\"scope\":\"uaa.admin orchestrator.zones.write zones.uaa.admin zones.write\"}",
                orchestratorZonesReadToken);
    }


    @Test
    void testCreateZone_unAuthorized_withoutAccessToken() throws Exception {
        OrchestratorZoneRequest orchestratorZoneRequest = getOrchestratorZoneRequest(ZONE_NAME,ADMIN_CLIENT_SECRET,
                                                                                     SUB_DOMAIN_NAME);
        MvcResult result = mockMvc
            .perform(
                post("/orchestrator/zones")
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(orchestratorZoneRequest)))
            .andExpect(status().isUnauthorized()).andReturn();
    }

    @Test
    void testCreateZone_Forbidden_InSufficientScope() throws Exception {
        OrchestratorZoneRequest orchestratorZoneRequest = getOrchestratorZoneRequest(ZONE_NAME,ADMIN_CLIENT_SECRET,
                                                                                     SUB_DOMAIN_NAME);
        MvcResult result = mockMvc
            .perform(
                post("/orchestrator/zones")
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(orchestratorZoneRequest))
                    .header("Authorization", "Bearer " + orchestratorZonesReadToken))
            .andExpect(status().isForbidden()).andReturn();
        assertTrue(result.getResponse().getContentAsString().contains("Insufficient scope for this resource"));
    }

    @ParameterizedTest
    @ArgumentsSource(SpaceAndEmptyArgumentsSource.class)
    void testCreateZone_nameAsSpaceAndEmptyError(String name) throws Exception {
        OrchestratorZoneRequest orchestratorZoneRequest = getOrchestratorZoneRequest(name,ADMIN_CLIENT_SECRET,SUB_DOMAIN_NAME);
        MvcResult result = mockMvc
            .perform(
                post("/orchestrator/zones")
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(orchestratorZoneRequest))
                    .header("Authorization", "Bearer " + orchestratorZonesWriteToken))
            .andExpect(status().isBadRequest()).andReturn();
        assertEquals(APPLICATION_JSON_VALUE, result.getResponse().getContentType());
        assertTrue(result.getResponse().getContentAsString().contains("name must not be blank"));
    }

    @ParameterizedTest
    @ArgumentsSource(SubDomainWithSpaceOrSpecialCharArguments.class)
    void testCreateZone_subDomainWithSpaceOrSpecialCharFail(String subDomain) throws Exception {
        OrchestratorZoneRequest orchestratorZoneRequest = getOrchestratorZoneRequest(ZONE_NAME,ADMIN_CLIENT_SECRET,
                                                                                     subDomain);
        MvcResult result = mockMvc
            .perform(
                post("/orchestrator/zones")
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(orchestratorZoneRequest))
                    .header("Authorization", "Bearer " + orchestratorZonesWriteToken))
            .andExpect(status().isBadRequest()).andReturn();
        assertEquals(APPLICATION_JSON_VALUE, result.getResponse().getContentType());
        assertTrue(result.getResponse().getContentAsString().contains("parameters.subdomain " +
                                                                      "is invalid. Special characters are not allowed in the " +
                                                                      "subdomain name except hyphen which can be specified in the middle"));
    }

    @ParameterizedTest
    @ArgumentsSource(SpaceAndEmptyArgumentsSource.class)
    void testCreateZone_adminClientSecretAsSpaceAndEmptyError(String adminClientSecret) throws Exception {
        OrchestratorZoneRequest orchestratorZoneRequest = getOrchestratorZoneRequest(ZONE_NAME,adminClientSecret,
                                                                                     SUB_DOMAIN_NAME);
        MvcResult result = mockMvc
            .perform(
                post("/orchestrator/zones")
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(orchestratorZoneRequest))
                    .header("Authorization", "Bearer " + orchestratorZonesWriteToken))
            .andExpect(status().isBadRequest()).andReturn();

        assertEquals(APPLICATION_JSON_VALUE, result.getResponse().getContentType());
        assertTrue(result.getResponse().getContentAsString().contains("parameters.adminClientSecret " +
                                                                      "must not be empty and must not have empty spaces"));
    }

    @Test
    void testCreateZone_Accepted_Success() throws Exception {
        createOrchestratorZoneAndAssert();
    }

    private void createOrchestratorZoneAndAssert() throws Exception {
        OrchestratorZoneRequest orchestratorZoneRequest = getOrchestratorZoneRequest(ZONE_NAME,ADMIN_CLIENT_SECRET,
                                                                                     SUB_DOMAIN_NAME);
        MvcResult result = mockMvc
            .perform(
                post("/orchestrator/zones")
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(orchestratorZoneRequest))
                    .header("Authorization", "Bearer " + orchestratorZonesWriteToken))
            .andExpect(status().isAccepted()).andReturn();
    }

    @Test
    void testCreateZone_MessageNotReadable_InvalidFormatError() throws Exception {
        MvcResult result = mockMvc
            .perform(
                post("/orchestrator/zones")
                    .contentType(APPLICATION_JSON)
                    .content("[[[[ ]]]]")
                    .header("Authorization", "Bearer " + orchestratorZonesWriteToken))
            .andExpect(status().isBadRequest()).andReturn();

        assertEquals(APPLICATION_JSON_VALUE, result.getResponse().getContentType());
        assertTrue(result.getResponse().getContentAsString().contains("Request failed due to a validation error"));
    }

    @Test
    void testCreateZone_MessageNotReadable_JsonMappingException() throws Exception {
        MvcResult result = mockMvc
            .perform(
                post("/orchestrator/zones")
                    .contentType(APPLICATION_JSON)
                    .content("{\n" +
                             "  \"name\": \"tes5000-00\",\n" +
                             "  \"parameters\": {\n" +
                             "    \"adminClientSecret\": 0992932.303203.00223\n" +
                             "    \"subdomain\" : \"uywyyw\"\n" +
                             "  }\n" +
                             "}")
                    .header("Authorization", "Bearer " + orchestratorZonesWriteToken))
            .andExpect(status().isBadRequest()).andReturn();

        assertEquals(APPLICATION_JSON_VALUE, result.getResponse().getContentType());
        assertTrue(result.getResponse().getContentAsString().contains("parameters is invalid: Invalid numeric value"));
    }

    @Test
    void testCreateZone_MessageNotReadable_MismatchedInputException() throws Exception {
        MvcResult result = mockMvc
            .perform(
                post("/orchestrator/zones")
                    .contentType(APPLICATION_JSON)
                    .content("{\n" +
                             "  \"name\": [\"323231\", \"323232\", \"323233\"],\n" +
                             "  \"parameters\": {\n" +
                             "    \"adminClientSecret\": \"dsfds\",\n" +
                             "    \"subdomain\" : \"test-zone-0\"\n" +
                             "  }\n" +
                             "}")
                    .header("Authorization", "Bearer " + orchestratorZonesWriteToken))
            .andExpect(status().isBadRequest()).andReturn();

        assertEquals(APPLICATION_JSON_VALUE, result.getResponse().getContentType());
        assertTrue(result.getResponse().getContentAsString().contains("name is invalid: Cannot deserialize value of type " +
                                                                      "`java.lang.String` from Array value"));
    }

    @Test
    void testCreateZone_MessageNotReadable_JsonParsingException() throws Exception {
        MvcResult result = mockMvc
            .perform(
                post("/orchestrator/zones")
                    .contentType(APPLICATION_JSON)
                    .content("{\n" +
                             "  \"name\": \"tes5000-00\",\n" +
                             "}")
                    .header("Authorization", "Bearer " + orchestratorZonesWriteToken))
            .andExpect(status().isBadRequest()).andReturn();

        assertEquals(APPLICATION_JSON_VALUE, result.getResponse().getContentType());
        assertTrue(result.getResponse().getContentAsString().contains("Unexpected character"));
    }

    @Test
    void testCreateZone_WithoutPayload() throws Exception {
        MvcResult result = mockMvc
            .perform(
                post("/orchestrator/zones")
                    .contentType(APPLICATION_JSON)
                    .content("")
                    .header("Authorization", "Bearer " + orchestratorZonesWriteToken))
            .andExpect(status().isBadRequest()).andReturn();

        assertEquals(APPLICATION_JSON_VALUE, result.getResponse().getContentType());
        assertTrue(result.getResponse().getContentAsString().contains("Required request body is missing"));
    }

    private static class IdentityZonesBaseUrlsArgumentsSource implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                Arguments.of("/orchestrator/zones"),
                Arguments.of("/orchestrator/zones/"),
                Arguments.of("/orchestrator/zones/test")
                            );
        }
    }

    private static class NameNotEmptyArgumentsSource implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                Arguments.of("/orchestrator/zones?name="),
                Arguments.of("/orchestrator/zones?name= ")
                            );
        }
    }

    private static class NameRequiredArgumentsSource implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                Arguments.of("/orchestrator/zones?name"),
                Arguments.of("/orchestrator/zones")
                            );
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

    private static class SpaceAndEmptyArgumentsSource implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                Arguments.of(""),
                Arguments.of(" ")
                            );
        }
    }

    private static class SubDomainWithSpaceOrSpecialCharArguments implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                Arguments.of("     "),
                Arguments.of("sub#-domain"),
                Arguments.of("sub    domain"),
                Arguments.of("-subdomainStartsWithHYphen"),
                Arguments.of("subdomainEndsWithHYphen-"),
                Arguments.of("sub\\\\domaincontainsslash"),
                Arguments.of("sub$%domaincontainsSpecialChars")
                            );
        }
    }
}
