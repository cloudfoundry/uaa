package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;

import static org.junit.Assert.*;

@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
public class IdentityZoneEndpointsIntegrationTests {
    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    private RestTemplate client;

    @Before
    public void createRestTemplate() throws Exception {
        client = (RestTemplate)serverRunning.getRestTemplate();
        client.setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) throws IOException {
            }
        });
    }

    @Test
    public void testCreateZone() {
        IdentityZone idZone = new IdentityZone();
        idZone.setHostname("subdomain.domain.io");
        idZone.setName("twiglet service");

        ResponseEntity<IdentityZone> responseEntity = client.postForEntity(serverRunning.getUrl("/identity-zones"), idZone, IdentityZone.class);

        assertEquals("subdomain.domain.io", responseEntity.getBody().getHostname());
        assertEquals("twiglet service", responseEntity.getBody().getName());
        assertNotNull(responseEntity.getBody().getId());
    }
}
