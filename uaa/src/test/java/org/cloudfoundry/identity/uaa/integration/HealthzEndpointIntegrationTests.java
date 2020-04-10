
package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * @author Dave Syer
 */
public class HealthzEndpointIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    /**
     * tests a happy-day flow of the <code>/healthz</code> endpoint
     */
    @Test
    public void testHappyDay() {

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<String> response = serverRunning.getForString("/healthz/", headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());

        String body = response.getBody();
        assertTrue(body.contains("ok"));

    }

}
