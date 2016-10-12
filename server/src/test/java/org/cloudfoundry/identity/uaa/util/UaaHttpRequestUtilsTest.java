package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLHandshakeException;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.getNoValidatingClientHttpRequestFactory;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.springframework.http.HttpStatus.OK;

public class UaaHttpRequestUtilsTest {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    @Test
    public void skipSslValidation() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setRequestFactory(getNoValidatingClientHttpRequestFactory());
        assertEquals(OK, restTemplate.getForEntity("https://login.identity.cf-app.com/info", Map.class).getStatusCode());

        restTemplate.setRequestFactory(UaaHttpRequestUtils.createRequestFactory(true));
        assertEquals(OK, restTemplate.getForEntity("https://login.identity.cf-app.com/info", Map.class).getStatusCode());
    }


    @Test
    public void trustedOnly() {
        RestTemplate restTemplate = new RestTemplate();
        try {
            restTemplate.getForEntity("https://login.identity.cf-app.com/info", Map.class);
            fail("We should not reach this step if the above URL is using a self signed certificate");
        } catch (RestClientException e) {
            assertEquals(SSLHandshakeException.class, e.getCause().getClass());
        }
    }
}