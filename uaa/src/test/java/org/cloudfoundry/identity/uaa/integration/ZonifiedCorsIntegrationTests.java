package org.cloudfoundry.identity.uaa.integration;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.zone.CorsConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

public class ZonifiedCorsIntegrationTests {
    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private static String baseUrl = "http://localhost:8080/uaa";


    @Test
    public void testZonifiedCorsFilter() {
        String zoneId = "testzone3";

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(Arrays.asList("other.com$"));
        config.getCorsPolicy().setDefaultConfiguration(corsConfiguration);
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, config);
        String zoneUrl = baseUrl.replace("localhost",zoneId+".localhost");

        RestTemplate template = new RestTemplate();
        //set request factory so restricted headers will be sent
        template.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        HttpHeaders failHeaders = new HttpHeaders();
        failHeaders.add(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET");
        failHeaders.add(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, AUTHORIZATION + ", " + ACCEPT + ", " + CONTENT_TYPE);
        failHeaders.add(HttpHeaders.ORIGIN, "wrong.com");
        HttpEntity<String> failEntity = new HttpEntity<>(null, failHeaders);
        try {
            template.exchange(zoneUrl + "/userinfo", HttpMethod.OPTIONS, failEntity, String.class);
            Assert.fail("Expected HttpClientErrorException to be thrown with a 403.");
        } catch(HttpClientErrorException e) {
            assertEquals(HttpStatus.FORBIDDEN, e.getStatusCode());
        }

        HttpHeaders successHeaders = new HttpHeaders();
        successHeaders.add(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET");
        successHeaders.add(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, AUTHORIZATION + ", " + ACCEPT + ", " + CONTENT_TYPE);
        successHeaders.add(HttpHeaders.ORIGIN, "other.com");
        HttpEntity<String> successEntity = new HttpEntity<>(null, successHeaders);
        ResponseEntity<String> response = template.exchange(zoneUrl + "/userinfo", HttpMethod.OPTIONS, successEntity, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }
}
