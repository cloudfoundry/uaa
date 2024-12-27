package org.cloudfoundry.identity.uaa.integration;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_NONE;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

public class PasswordGrantIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    RandomValueStringGenerator generator = new RandomValueStringGenerator(36);

    @Test
    public void testUserLoginViaPasswordGrant_usingClientWithEmptyClientSecret() {
        ResponseEntity<String> responseEntity = makePasswordGrantRequest(testAccounts.getUserName(), testAccounts.getPassword(), "cf", "", serverRunning.getAccessTokenUri());
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        validateClientAuthenticationMethod(responseEntity, true);
    }

    @Test
    public void testUserLoginViaPasswordGrant_usingConfidentialClient() {
        ResponseEntity<String> responseEntity = makePasswordGrantRequest(testAccounts.getUserName(), testAccounts.getPassword(), "app", "appclientsecret", serverRunning.getAccessTokenUri());
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        validateClientAuthenticationMethod(responseEntity, false);
    }

    @Test
    public void password_grant_returns_correct_error() throws Exception {
        UaaClientDetails client = addUserGroupsRequiredClient();
        ResponseEntity<String> responseEntity = makePasswordGrantRequest(testAccounts.getUserName(), testAccounts.getPassword(), client.getClientId(), "secret", serverRunning.getAccessTokenUri());
        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
        assertEquals(APPLICATION_JSON_VALUE, responseEntity.getHeaders().get("Content-Type").get(0));
        Map<String, Object> errors = JsonUtils.readValue(responseEntity.getBody(), new TypeReference<Map<String, Object>>() {
        });
        assertEquals("User does not meet the client's required group criteria.", errors.get("error_description"));
        assertEquals("invalid_scope", errors.get("error"));
    }

    @Test
    public void passwordGrantInactiveZone() {
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                        new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));
        IntegrationTestUtils.createInactiveIdentityZone(identityClient, "http://localhost:8080/uaa");
        String accessTokenUri = serverRunning.getAccessTokenUri().replace("localhost", "testzoneinactive.localhost");
        ResponseEntity<String> response = makePasswordGrantRequest(testAccounts.getUserName(), testAccounts.getPassword(), "cf", "", accessTokenUri);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    public void passwordGrantNonExistingZone() {
        String accessTokenUri = serverRunning.getAccessTokenUri().replace("localhost", "testzonedoesnotexist.localhost");
        ResponseEntity<String> response = makePasswordGrantRequest(testAccounts.getUserName(), testAccounts.getPassword(), "cf", "", accessTokenUri);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    protected UaaClientDetails addUserGroupsRequiredClient() {
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(
                serverRunning.getBaseUrl(),
                "admin",
                "adminsecret"
        );
        UaaClientDetails client = new UaaClientDetails(
                generator.generate(),
                null,
                "openid",
                "password",
                null
        );
        client.setClientSecret("secret");
        Map<String, Object> additional = new HashMap();
        additional.put(ClientConstants.REQUIRED_USER_GROUPS, Collections.singletonList("non.existent"));
        client.setAdditionalInformation(additional);

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(APPLICATION_JSON));
        headers.add("Authorization", "Bearer " + adminToken);
        headers.setContentType(APPLICATION_JSON);

        HttpEntity<String> request = new HttpEntity<>(JsonUtils.writeValueAsString(client), headers);

        ResponseEntity<String> response = new RestTemplate().postForEntity(serverRunning.getUrl("/oauth/clients"), request, String.class);
        assertEquals(201, response.getStatusCodeValue());

        return JsonUtils.readValue(response.getBody(), UaaClientDetails.class);
    }

    protected static ResponseEntity<String> makePasswordGrantRequest(String userName, String password, String clientId, String clientSecret, String url) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(APPLICATION_JSON));
        headers.add("Authorization", UaaTestAccounts.getAuthorizationHeader(clientId, clientSecret));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("username", userName);
        params.add("password", password);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        RestTemplate template = getRestTemplate();
        return template.postForEntity(url, request, String.class);
    }

    protected static RestTemplate getRestTemplate() {
        RestTemplate template = new RestTemplate();
        template.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return response.getRawStatusCode() >= 500;
            }

            @Override
            public void handleError(ClientHttpResponse response) {

            }
        });
        return template;
    }

    protected static String validateClientAuthenticationMethod(ResponseEntity<String> responseEntity, boolean isNone) {
        Map<String, Object> jsonBody = JsonUtils.readValue(responseEntity.getBody(), new TypeReference<Map<String, Object>>() {
        });
        String accessToken = (String) jsonBody.get("access_token");
        assertThat(accessToken, is(notNullValue()));
        Map<String, Object> claims = UaaTokenUtils.getClaims(accessToken, Map.class);
        if (isNone) {
            assertThat(claims, hasEntry(ClaimConstants.CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
        } else {
            assertThat(claims, not(hasKey(ClaimConstants.CLIENT_AUTH_METHOD)));
        }
        return (String) jsonBody.get("refresh_token");
    }
}
