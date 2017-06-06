package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.getNoValidatingClientHttpRequestFactory;
import static org.springframework.http.HttpStatus.OK;

public class UaaHttpRequestUtilsTest {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    @Test
    public void skipSslValidation() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setRequestFactory(getNoValidatingClientHttpRequestFactory());
        Assert.assertEquals(OK, restTemplate.getForEntity("https://login.uaa-acceptance.cf-app.com/info", Map.class).getStatusCode());
    }
}