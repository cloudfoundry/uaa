package org.cloudfoundry.identity.uaa.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ge.predix.iam.kubernetes.enums.ApiEnvironment;
import com.ge.predix.iam.kubernetes.enums.ServiceName;
import com.ge.predix.iam.kubernetes.exception.ServiceInstanceProviderException;
import com.ge.predix.iam.kubernetes.model.Claim;
import com.ge.predix.iam.kubernetes.model.uaa.UaaClaimSpec;
import com.ge.predix.iam.kubernetes.model.uaa.UaaForProvider;
import com.ge.predix.iam.kubernetes.model.uaa.UaaRequest;
import com.ge.predix.iam.kubernetes.utils.OrchestratorUtil;
import io.kubernetes.client.openapi.ApiException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;

import java.util.Random;
import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = OrchestratorIntegrationTestConfig.class)
@Slf4j
public class OrchestratorClaimAT {
    protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final Logger LOGGER = LoggerFactory.getLogger(OrchestratorClaimAT.class);

    private static final String UAA_ADMIN_CLIENT_SECRET = "ZHVtbXlBZG1pblNlY3JldDEyMyMh";

    private static final String UAA_CLAIM_NAME_PREFIX = "uaa-it-";

    public static final String ZONES_URI = "/orchestrator/zones";

    private static HttpHeaders headers;

    private Random random = new Random();

    private final String UAA_SUBDOMAIN = "rest-uaa-subdomain" + random.nextInt(1000);

    @Value("${uaa.url}")
    private String uaaUrl;

    @Value("${uaa.orchestrator.clientId}")
    private String clientId;

    @Value("${uaa.orchestrator.clientSecret}")
    private String clientSecret;

    @Value("${kubernetes.config.env}")
    private String environment;

    @Autowired
    private OrchestratorUtil orchestratorUtil;

    protected static OAuth2RestTemplate trustedIssuerValidScopesRestTemplate;

    @Value("${kubernetes.config.secondary-namespace:iamqa-svc}")
    private String namespace;

    private Integer uaaInstanceCount = random.nextInt(1000);

    // region Positive Tests

    @Test
    public void testCreateZoneWithSubdomain() throws Exception {
        testCreateZone(UAA_SUBDOMAIN, UAA_ADMIN_CLIENT_SECRET);
    }

    @Test
    public void testCreateZoneWithOutSubdomain() throws Exception {
        testCreateZone(null, UAA_ADMIN_CLIENT_SECRET);
    }

    public void testCreateZone(String subDomain, String adminSecret) throws Exception {
        UaaRequest uaaRequest = new UaaRequest();
        uaaRequest.setSubdomain(subDomain);
        uaaRequest.setAdminClientSecret(adminSecret);
        String claimName;
        OrchestratorZoneResponse getZone = null;
        String zoneName = null;
        claimName = (UAA_CLAIM_NAME_PREFIX + (uaaInstanceCount)).toLowerCase();
        Claim claim = null;
        boolean isClaimCreated = false;
        try {
            isClaimCreated = createZone(claimName, uaaRequest);
            Thread.sleep(120000);
            claim = getZone(claimName, ServiceName.UAA);
            assertNotNull(claim);
            assertEquals(claimName, claim.getMetadata().getName());

            zoneName = namespace + "-" + claimName;
            String getResponse = getZoneByName(zoneName, HttpStatus.OK, null);
            getZone = OBJECT_MAPPER.readValue(getResponse, OrchestratorZoneResponse.class);

            //assertions from get API
            assertNotNull(getResponse);
            assertNotNull(getZone);
            assertEquals(zoneName, getZone.getName());
            assertNotNull(getZone.getConnectionDetails().getDashboardUri());
            assertNotNull(getZone.getConnectionDetails().getUri());
            assertNotNull(getZone.getConnectionDetails().getIssuerId());
            assertNotNull(getZone.getConnectionDetails().getZone().getHttpHeaderValue());
            assertNotNull(getZone.getConnectionDetails().getZone().getHttpHeaderName());
            if (uaaRequest.getSubdomain() != null) {
                assertEquals(uaaRequest.getSubdomain(), getZone.getConnectionDetails().getSubdomain());
            } else {
                assertNotNull(getZone.getConnectionDetails().getSubdomain());
            }
            JsonNode outputSecret = orchestratorUtil.readSecret(claimName, ServiceName.UAA);
            String outputSecretData = StringEscapeUtils.unescapeJava(outputSecret.toString());
            assertNotNull(outputSecret);
            assertNotNull(outputSecretData);
            JsonNode connection = outputSecret.get("connectionDetails");
            JsonNode connectionSecret = OBJECT_MAPPER.readTree(connection.asText());

            // if claim and outputSecret(created by Orchestrator as result of successful instance creation) both are not null
            // that means uaa zone is successfully created in uaa service.
            UaaForProvider uaaforProvider = ((UaaClaimSpec) claim.getSpec()).getUaaForProvider();

            //assertions from Claim.
            assertNotNull(connection);
            if (uaaRequest.getSubdomain() != null) {
                assertEquals(uaaRequest.getSubdomain(), connectionSecret.get("subdomain").asText());
            } else {
                assertNotNull(connectionSecret.get("subdomain"));
            }
            assertEquals(getZone.getConnectionDetails().getUri(), connectionSecret.get("uri").asText());
            assertEquals(getZone.getConnectionDetails().getDashboardUri(), connectionSecret.get("dashboardUrl").asText());
            assertEquals(getZone.getConnectionDetails().getIssuerId(), connectionSecret.get("issuerId").asText());
            assertEquals(getZone.getConnectionDetails().getZone().getHttpHeaderName(), connectionSecret.get("zone").get("http-header-name").asText());
            assertEquals(getZone.getConnectionDetails().getZone().getHttpHeaderValue(), connectionSecret.get("zone").get("http-header-value").asText());
        } finally {
            if (isClaimCreated) {
                deleteZone(claimName, ServiceName.UAA);
            }
            if (getZone != null) {
                Thread.sleep(20000);
                getZoneByName(zoneName, HttpStatus.NOT_FOUND, "Zone[" + zoneName + "] not found.");
            }
        }
    }
    // end region Positive Tests

    // region Negative Tests"
    @Test
    public void testCreateZoneWithBadInput() throws Exception {
        UaaRequest uaaRequest = new UaaRequest();
        uaaRequest.setSubdomain(UAA_SUBDOMAIN);
        uaaRequest.setAdminClientSecret(UAA_ADMIN_CLIENT_SECRET);
        String claimName = null;
        boolean isClaimCreated = false;
        try {
            isClaimCreated = createZone(claimName, uaaRequest);
            Claim claim = getZone(claimName, ServiceName.UAA);
            assertNull("Orchestrator should not create UAA instance for Bad Input", claim);
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("Kubernetes API Exception occurred during Claim creation"));
        } finally {
            if (isClaimCreated) {
                deleteZone(claimName, ServiceName.UAA);
            }
        }
    }

    @Test
    public void testGetZoneForNonExisting() throws Exception {
        String dummyClaimName = (UAA_CLAIM_NAME_PREFIX + "Non_existent_run_id_12345").toLowerCase();
        try {
            Claim claim = getZone(dummyClaimName, ServiceName.UAA);
            assertNull("Orchestrator should return null for Non existing zone", claim);
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("Service claim " + dummyClaimName + " does not exist"));
        }
    }

    @Test
    public void testDeleteZoneForNonExisting() throws Exception {
        String dummyClaimName = (UAA_CLAIM_NAME_PREFIX + "Non_existent_run_id_12345").toLowerCase();
        try {
            deleteZone(dummyClaimName, ServiceName.UAA);
        } catch (Exception e) {
            LOGGER.error("error while deleting non existing zone", e);
            assertTrue(e.getMessage().contains("Service claim " + dummyClaimName + " does not exist"));
        }
    }
    // end region Negative Tests

    private boolean createZone(final String claimName, final UaaRequest uaaRequest)
            throws ServiceInstanceProviderException, ApiException {
        try {
            orchestratorUtil.createService(claimName, ServiceName.UAA, OBJECT_MAPPER.valueToTree(uaaRequest), ApiEnvironment.valueOf(environment));
            return true;
        } catch (ServiceInstanceProviderException | ApiException e) {
            LOGGER.error("UAA Claim create failed for claimName: {}, uaaRequest:{}, errorMessage: {}", claimName, uaaRequest, e.getMessage(), e);
            throw e;
        }
    }

    private Claim getZone(final String claimName, final ServiceName serviceName) throws ServiceInstanceProviderException {
        try {
            return orchestratorUtil.readClaim(claimName, ServiceName.UAA, ApiEnvironment.valueOf(environment));
        } catch (ServiceInstanceProviderException e) {
            LOGGER.error("UAA Claim read failed for claimName: {}, errorMessage: {}", claimName, e.getMessage(), e);
            throw e;
        }
    }

    private boolean deleteZone(final String claimName, final ServiceName serviceName) throws ServiceInstanceProviderException {
        try {
            orchestratorUtil.deleteClaim(claimName, ServiceName.UAA, ApiEnvironment.valueOf(environment));
            return true;
        } catch (ServiceInstanceProviderException e) {
            LOGGER.error("UAA Claim delete failed for claimName: {}, errorMessage: {}", claimName, e.getMessage(), e);
            throw e;
        }
    }

    private String getZoneByName(final String zoneName, HttpStatus status, String expectedErrorMessage) throws Exception {
        if (StringUtils.isEmpty(zoneName)) {
            throw new Exception("zoneName can not be null");
        }
        String url = uaaUrl + ZONES_URI + "?name=" + zoneName;
        return executeRequest(getZoneRestTemplate(), url, HttpMethod.GET, headers, status, expectedErrorMessage,
                null);
    }

    protected RestTemplate getZoneRestTemplate() {
        RestTemplate Zone = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(uaaUrl, new String[0], clientId, clientSecret)
        );
        return Zone;
    }

    public static String executeRequest(RestTemplate tenantRestTemplate, String url, HttpMethod method,
                                        HttpHeaders headers, HttpStatus expectedStatusCode,
                                        String expectedMessage, String requestBody) {
        String body = null;
        if (!HttpMethod.GET.equals(method)) {
            body = requestBody;
        }
        HttpEntity<String> request = new HttpEntity<>(body, headers);
        log.trace("Executing HTTP {} - url: {}, request:\n {}", method, url, request);
        if (!expectedStatusCode.is2xxSuccessful()) {
            ResponseEntity<OrchestratorZoneResponse> responseEntity = tenantRestTemplate.exchange(url, method, request, OrchestratorZoneResponse.class);
            log.trace("HTTP Response: {}", responseEntity);
            assertNotNull(responseEntity);
            assertEquals("Unexpected response: " + responseEntity.getBody(),
                    expectedStatusCode, responseEntity.getStatusCode());
            OrchestratorZoneResponse restResponse = responseEntity.getBody();
            assertNotNull(restResponse);
            String message = restResponse.getMessage();
            assertEquals(expectedMessage, message);
            return message;
        } else {
            log.debug("Request: {}", request);
            ResponseEntity<String> response = tenantRestTemplate.exchange(url, method, request, String.class);
            log.debug("Response: {}", response);
            assertNotNull(response);
            assertEquals("Unexpected response: " + response.getBody(), expectedStatusCode, response.getStatusCode());
            return response.getBody();
        }
    }
}