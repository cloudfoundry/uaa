package org.cloudfoundry.identity.uaa.integration;

import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.cloudfoundry.identity.uaa.oauth.client.http.OAuth2ErrorHandler;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextConfiguration;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextExtension;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;

@OAuth2ContextConfiguration(IdentityZoneEndpointsIntegrationTests.IdentityClient.class)
class IdentityZoneEndpointsIntegrationTests {
    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    @RegisterExtension
    private static final OAuth2ContextExtension context = OAuth2ContextExtension.withTestAccounts(serverRunning, testAccountExtension);

    private RestTemplate client;
    private String zoneId;

    @BeforeEach
    void createRestTemplate() {
        client = (OAuth2RestTemplate) serverRunning.getRestTemplate();
        client.setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
                // pass through
            }
        });
    }

    @AfterEach
    void cleanup() {
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        RestTemplate client = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(), new String[0], "admin", "adminsecret")
        );
        String groupId = IntegrationTestUtils.findGroupId(client, serverRunning.getBaseUrl(), "zones.%s.admin".formatted(zoneId));
        if (groupId != null) {
            IntegrationTestUtils.deleteGroup(clientCredentialsToken, "", serverRunning.getBaseUrl(), groupId);
        }
    }

    @Test
    void createZone() {
        zoneId = UUID.randomUUID().toString();
        String requestBody = "{\"id\":\"" + zoneId + "\", \"subdomain\":\"" + zoneId + "\", \"name\":\"testCreateZone() " + zoneId + "\"}";

        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        ResponseEntity<Void> response = client.exchange(
                serverRunning.getUrl("/identity-zones"),
                HttpMethod.POST,
                new HttpEntity<>(requestBody, headers),
                new ParameterizedTypeReference<>() {
                });

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(), new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, serverRunning.getBaseUrl(), email, "firstname", "lastname", email, true);

        ScimGroup scimGroup = new ScimGroup(null, "zones.%s.admin".formatted(zoneId), null);
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

        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        ResponseEntity<List<IdentityProvider>> idpList = new RestTemplate().exchange(
                serverRunning.getUrl("/identity-providers"),
                HttpMethod.GET,
                new HttpEntity<>(null, headers),
                new ParameterizedTypeReference<>() {
                });

        IdentityProvider identityProvider = idpList.getBody().getFirst();
        assertThat(identityProvider.getIdentityZoneId()).isEqualTo(zoneId);
        assertThat(identityProvider.getOriginKey()).isEqualTo(OriginKeys.UAA);

        //the default created zone does have a definition, but no policy
        assertThat(identityProvider.getConfig()).isNotNull();
        assertThat(ObjectUtils.castInstance(identityProvider.getConfig(), UaaIdentityProviderDefinition.class).getPasswordPolicy()).isNull();
    }

    @Test
    void updateZoneAllowedGroups() {
        IdentityZone idZone = new IdentityZone();
        String id = UUID.randomUUID().toString();
        idZone.setId(id);
        idZone.setSubdomain(id);
        idZone.setName("testUpdateZone-" + id);
        ResponseEntity<String> response = client.exchange(
                serverRunning.getUrl("/identity-zones"),
                HttpMethod.POST,
                new HttpEntity<>(idZone),
                new ParameterizedTypeReference<>() {
                },
                id);
        assertThat(response.getStatusCode()).as(response.getBody()).isEqualTo(HttpStatus.CREATED);

        List<String> existingGroups = List.of("sps.write", "sps.read", "idps.write", "idps.read", "clients.admin", "clients.write", "clients.read",
                "clients.secret", "scim.write", "scim.read", "scim.create", "scim.userids", "scim.zones", "groups.update", "password.write", "oauth.login", "uaa.admin");
        idZone.getConfig().getUserConfig().setAllowedGroups(existingGroups);
        response = client.exchange(
                serverRunning.getUrl("/identity-zones/" + id),
                HttpMethod.PUT,
                new HttpEntity<>(idZone),
                new ParameterizedTypeReference<>() {
                },
                id);
        assertThat(response.getStatusCode()).as(response.getBody()).isEqualTo(HttpStatus.OK);

        List<String> notAllExistingGroups = List.of("clients.admin", "clients.write", "clients.read", "clients.secret");
        idZone.getConfig().getUserConfig().setAllowedGroups(notAllExistingGroups);
        response = client.exchange(
                serverRunning.getUrl("/identity-zones/" + id),
                HttpMethod.PUT,
                new HttpEntity<>(idZone),
                new ParameterizedTypeReference<>() {
                },
                id);
        assertThat(response.getStatusCode()).as(response.getBody()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @Test
    void createZoneWithClient() {
        IdentityZone idZone = new IdentityZone();
        String id = UUID.randomUUID().toString();
        idZone.setId(id);
        idZone.setSubdomain(id);
        idZone.setName("testCreateZone() " + id);
        ResponseEntity<Void> response = client.exchange(
                serverRunning.getUrl("/identity-zones"),
                HttpMethod.POST,
                new HttpEntity<>(idZone),
                new ParameterizedTypeReference<>() {
                },
                id);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        UaaClientDetails clientDetails = new UaaClientDetails("test123", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        clientDetails.setClientSecret("testSecret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singleton(OriginKeys.UAA));

        ResponseEntity<Void> clientCreateResponse = client.exchange(
                serverRunning.getUrl("/identity-zones/" + id + "/clients"),
                HttpMethod.POST,
                new HttpEntity<>(clientDetails),
                new ParameterizedTypeReference<>() {
                },
                id);

        assertThat(clientCreateResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        ResponseEntity<Void> clientDeleteResponse = client.exchange(
                serverRunning.getUrl("/identity-zones/" + id + "/clients/" + clientDetails.getClientId()),
                HttpMethod.DELETE,
                null,
                new ParameterizedTypeReference<>() {
                },
                id);

        assertThat(clientDeleteResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void createZoneWithNonUniqueSubdomain() {
        IdentityZone idZone1 = new IdentityZone();
        String id1 = UUID.randomUUID().toString();
        idZone1.setId(id1);
        idZone1.setSubdomain(id1 + "non-unique");
        idZone1.setName("testCreateZone() " + id1);
        ResponseEntity<Void> response1 = client.exchange(
                serverRunning.getUrl("/identity-zones"),
                HttpMethod.POST,
                new HttpEntity<>(idZone1),
                new ParameterizedTypeReference<>() {
                },
                id1);
        assertThat(response1.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        IdentityZone idZone2 = new IdentityZone();
        String id2 = UUID.randomUUID().toString();
        idZone2.setId(id2);
        idZone2.setSubdomain(id1 + "non-unique");
        idZone2.setName("testCreateZone() " + id2);
        ResponseEntity<Map<String, String>> response2 = client.exchange(
                serverRunning.getUrl("/identity-zones"),
                HttpMethod.POST,
                new HttpEntity<>(idZone2),
                new ParameterizedTypeReference<>() {
                },
                id2);
        assertThat(response2.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response2.getBody().get("error_description").toLowerCase()).contains("subdomain");
    }

    static class IdentityClient extends ClientCredentialsResourceDetails {
        public IdentityClient(Object target) {
            IdentityZoneEndpointsIntegrationTests test = (IdentityZoneEndpointsIntegrationTests) target;
            ClientCredentialsResourceDetails resource = test.testAccounts.getClientCredentialsResource(
                    new String[]{"zones.write"}, "identity", "identitysecret");
            setClientId(resource.getClientId());
            setClientSecret(resource.getClientSecret());
            setId(getClientId());
            setAccessTokenUri(test.serverRunning.getAccessTokenUri());
        }
    }
}
