
package org.cloudfoundry.identity.uaa.integration;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class LoginInfoEndpointIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    /**
     * tests a happy-day flow of the <code>/info</code> endpoint
     */
    @Test
    public void testHappyDay() {

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject("/info", Map.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String[]> prompts = (Map<String, String[]>) response.getBody().get("prompts");
        assertNotNull(prompts);

    }

    /**
     * tests a happy-day flow of the <code>/login</code> endpoint
     */
    @Test
    public void testHappyDayHtml() {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.TEXT_HTML));
        ResponseEntity<String> response = serverRunning.getForString("/login", headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        String body = response.getBody();
        // System.err.println(body);
        assertNotNull(body);
        assertTrue("Wrong body: " + body, body.contains("<form action=\"/uaa/login.do\" method=\"post\" novalidate=\"novalidate\" accept-charset=\"UTF-8\">"));

    }

}
