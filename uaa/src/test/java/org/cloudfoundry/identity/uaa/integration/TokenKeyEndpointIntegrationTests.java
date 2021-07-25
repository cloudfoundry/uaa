package org.cloudfoundry.identity.uaa.integration;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;

import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class TokenKeyEndpointIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Test
    public void testTokenKey() {
        HttpHeaders headers = new HttpHeaders();
        ClientCredentialsResourceDetails resource = testAccounts.getClientCredentialsResource("app", null, "app",
                "appclientsecret");
        headers.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject("/token_key", Map.class, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String> map = response.getBody();
        assertNotNull(map.get("alg"));
        assertNotNull(map.get("value"));
    }
}
