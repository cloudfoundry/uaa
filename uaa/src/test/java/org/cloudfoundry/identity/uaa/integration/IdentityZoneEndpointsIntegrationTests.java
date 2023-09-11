package org.cloudfoundry.identity.uaa.integration;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.OrchestratorState;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.web.client.RestTemplate;

import java.util.*;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService.ZONE_CREATED_MESSAGE;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

@OAuth2ContextConfiguration(IdentityZoneEndpointsIntegrationTests.IdentityClient.class)
public class IdentityZoneEndpointsIntegrationTests {
    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    private RestTemplate client;
    private String zoneId;

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

    @After
    public void cleanup() {
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        RestTemplate client = IntegrationTestUtils.getClientCredentialsTemplate(
          IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(), new String[0], "admin", "adminsecret")
        );
        String groupId = IntegrationTestUtils.findGroupId(client, serverRunning.getBaseUrl(), String.format("zones.%s.admin", zoneId));
        if (groupId != null) {
            IntegrationTestUtils.deleteGroup(clientCredentialsToken, "", serverRunning.getBaseUrl(), groupId);
        }
    }

    @Test
    public void testCreateZone() {
        zoneId = UUID.randomUUID().toString();
        String requestBody = "{\"id\":\""+ zoneId +"\", \"subdomain\":\""+ zoneId +"\", \"name\":\"testCreateZone() "+ zoneId +"\"}";

        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        ResponseEntity<Void> response = client.exchange(
                serverRunning.getUrl("/identity-zones"),
                HttpMethod.POST,
                new HttpEntity<>(requestBody, headers),
                new ParameterizedTypeReference<Void>() {});

        assertEquals(HttpStatus.CREATED, response.getStatusCode());

        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(), new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, serverRunning.getBaseUrl(), email, "firstname", "lastname", email, true);

        ScimGroup scimGroup = new ScimGroup(null, String.format("zones.%s.admin", zoneId), null);
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        ScimGroup group = IntegrationTestUtils.createGroup(clientCredentialsToken, "", serverRunning.getBaseUrl(), scimGroup);
        IntegrationTestUtils.addMemberToGroup(adminClient, serverRunning.getBaseUrl(), user.getId(), group.getId());

        String zoneAdminToken =
                IntegrationTestUtils.getAccessTokenByAuthCode(serverRunning,
                        UaaTestAccounts.standard(serverRunning),
                        "identity",
                        "identitysecret",
                        email,
                        "secr3T");

        headers.add("Authorization", "bearer "+zoneAdminToken);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        ResponseEntity<List<IdentityProvider>> idpList = new RestTemplate().exchange(
                serverRunning.getUrl("/identity-providers"),
                HttpMethod.GET,
                new HttpEntity<>(null, headers),
                new ParameterizedTypeReference<List<IdentityProvider>>() {});

        assertTrue(idpList.getHeaders().getContentType().includes(MediaType.APPLICATION_JSON_UTF8));

        IdentityProvider identityProvider = idpList.getBody().get(0);
        assertThat(identityProvider.getIdentityZoneId(), is(zoneId));
        assertThat(identityProvider.getOriginKey(), is(OriginKeys.UAA));

        //the default created zone does have a definition, but no policy
        assertNotNull(identityProvider.getConfig());
        assertNull(ObjectUtils.castInstance(identityProvider.getConfig(),UaaIdentityProviderDefinition.class).getPasswordPolicy());
    }

    @Test
    public void testCreateZoneWithClient() {
        IdentityZone idZone = new IdentityZone();
        String id = UUID.randomUUID().toString();
        idZone.setId(id);
        idZone.setSubdomain(id);
        idZone.setName("testCreateZone() "+id);
        ResponseEntity<Void> response = client.exchange(
                serverRunning.getUrl("/identity-zones"),
                HttpMethod.POST,
                new HttpEntity<>(idZone),
                new ParameterizedTypeReference<Void>() {},
                id);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());

        BaseClientDetails clientDetails = new BaseClientDetails("test123", null,"openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        clientDetails.setClientSecret("testSecret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singleton(OriginKeys.UAA));

        ResponseEntity<Void> clientCreateResponse = client.exchange(
                serverRunning.getUrl("/identity-zones/"+id+"/clients"),
                HttpMethod.POST,
                new HttpEntity<>(clientDetails),
                new ParameterizedTypeReference<Void>() {},
                id);

        assertEquals(HttpStatus.CREATED, clientCreateResponse.getStatusCode());

        ResponseEntity<Void> clientDeleteResponse = client.exchange(
                serverRunning.getUrl("/identity-zones/"+id+"/clients/"+clientDetails.getClientId()),
                HttpMethod.DELETE,
                null,
                new ParameterizedTypeReference<Void>() {},
                id);

        assertEquals(HttpStatus.OK, clientDeleteResponse.getStatusCode());
    }


    @Test
    public void testCreateZoneWithNonUniqueSubdomain() {
        IdentityZone idZone1 = new IdentityZone();
        String id1 = UUID.randomUUID().toString();
        idZone1.setId(id1);
        idZone1.setSubdomain(id1+"non-unique");
        idZone1.setName("testCreateZone() "+id1);
        ResponseEntity<Void> response1 = client.exchange(
                serverRunning.getUrl("/identity-zones"),
                HttpMethod.POST,
                new HttpEntity<>(idZone1),
                new ParameterizedTypeReference<Void>() {},
                id1);
        assertEquals(HttpStatus.CREATED, response1.getStatusCode());

        IdentityZone idZone2 = new IdentityZone();
        String id2 = UUID.randomUUID().toString();
        idZone2.setId(id2);
        idZone2.setSubdomain(id1+"non-unique");
        idZone2.setName("testCreateZone() "+id2);
        ResponseEntity<Map<String,String>> response2 = client.exchange(
                serverRunning.getUrl("/identity-zones"),
                HttpMethod.POST,
                new HttpEntity<>(idZone2),
                new ParameterizedTypeReference<Map<String,String>>() {},
                id2);
        assertEquals(HttpStatus.CONFLICT, response2.getStatusCode());
        Assert.assertTrue(response2.getBody().get("error_description").toLowerCase().contains("subdomain"));
    }
    
    @Test
    public void testUpdateZoneWithDisableClientRedirectUri() throws Exception {
        String zoneId = UUID.randomUUID().toString();
        String requestBody = "{\"id\":\""+zoneId+"\", \"subdomain\":\""+zoneId+"\", \"name\":\"testCreateZone() "+zoneId+"\",\"enable_redirect_uri_check\":false}";

        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        ResponseEntity<IdentityZone> response = client.exchange(
                serverRunning.getUrl("/identity-zones"),
                HttpMethod.POST,
                new HttpEntity<>(requestBody, headers), IdentityZone.class);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertFalse(response.getBody().isEnableRedirectUriCheck());
        
        requestBody = "{\"id\":\""+zoneId+"\", \"subdomain\":\""+zoneId+"\", \"name\":\"testCreateZone() "+zoneId+"\" }";
        ResponseEntity<IdentityZone> updateResponse = client.exchange(
                serverRunning.getUrl("/identity-zones/" + zoneId),
                HttpMethod.PUT,
                new HttpEntity<>(requestBody, headers),
                IdentityZone.class);
        
        assertEquals(HttpStatus.OK, updateResponse.getStatusCode());
        assertTrue(updateResponse.getBody().isEnableRedirectUriCheck());
    }

    @Test
    public void testDeletePortedZone() {
        //Create Identity Zone
        IdentityZone idZone = new IdentityZone();
        String id = UUID.randomUUID().toString();
        idZone.setId(id);
        idZone.setSubdomain(id);
        idZone.setName("testCreateZone() " + id);
        ResponseEntity<Void> response = client.exchange(serverRunning.getUrl("/identity-zones"), HttpMethod.POST, new HttpEntity<>(idZone), new ParameterizedTypeReference<Void>() {
        }, id);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());

        //Port Zone and Validate
        ResponseEntity<Void> importResponse = portZone(id);
        OrchestratorZoneResponse expectedResponse = new OrchestratorZoneResponse();
        expectedResponse.setName(zoneId);
        expectedResponse.setMessage(ZONE_CREATED_MESSAGE);
        expectedResponse.setState(OrchestratorState.CREATE_IN_PROGRESS.toString());

        Assertions.assertEquals(HttpStatus.ACCEPTED, importResponse.getStatusCode());

        ResponseEntity<Void> deleteResponse = client.exchange(serverRunning.getUrl("/identity-zones/" + id), HttpMethod.DELETE, null, new ParameterizedTypeReference<Void>() {
        });

        Assertions.assertEquals(deleteResponse.getStatusCode(), HttpStatus.UNPROCESSABLE_ENTITY);
    }

    private ResponseEntity<Void> portZone(String zoneId) {
        ClientCredentialsResourceDetails orchestratorZoneClientCredentials = new ClientCredentialsResourceDetails();
        orchestratorZoneClientCredentials.setClientId("orchestrator-zone-provisioner");
        orchestratorZoneClientCredentials.setClientSecret("orchestratorsecret");
        orchestratorZoneClientCredentials.setId("orchestrator-zone-provisioner");
        orchestratorZoneClientCredentials.setAccessTokenUri("http://localhost:8080/uaa/oauth/token");
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(orchestratorZoneClientCredentials, new DefaultOAuth2ClientContext());
        String requestBody = JsonUtils.writeValueAsString(getOrchestratorImportZoneRequest("TestZone", "admin-secret", "TestZone", zoneId));
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        ResponseEntity<Void> response = restTemplate.exchange(serverRunning.getUrl("/orchestrator/zones"), HttpMethod.POST, new HttpEntity<>(requestBody, headers), new ParameterizedTypeReference<Void>() {
        });

        return response;
    }

    private OrchestratorZoneRequest getOrchestratorImportZoneRequest(String name, String adminClientSecret, String subdomain, String importServiceInstanceGuid) {
        OrchestratorZone orchestratorZone = new OrchestratorZone(adminClientSecret, subdomain, importServiceInstanceGuid);
        OrchestratorZoneRequest orchestratorZoneRequest = new OrchestratorZoneRequest();
        orchestratorZoneRequest.setName(name);
        orchestratorZoneRequest.setParameters(orchestratorZone);
        return orchestratorZoneRequest;
    }

    static class IdentityClient extends ClientCredentialsResourceDetails {
        public IdentityClient(Object target) {
            IdentityZoneEndpointsIntegrationTests test = (IdentityZoneEndpointsIntegrationTests) target;
            ClientCredentialsResourceDetails resource = test.testAccounts.getClientCredentialsResource(
                            new String[] {"zones.write"}, "identity", "identitysecret");
            setClientId(resource.getClientId());
            setClientSecret(resource.getClientSecret());
            setId(getClientId());
            setAccessTokenUri(test.serverRunning.getAccessTokenUri());
        }
    }

}
