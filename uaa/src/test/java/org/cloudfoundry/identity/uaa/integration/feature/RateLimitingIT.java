package org.cloudfoundry.identity.uaa.integration.feature;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestOperations;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class RateLimitingIT {

    @Autowired @Rule
    public IntegrationTestRule integrationTestRule;

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Before
    @After
    public void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        }catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }

    @Test
    public void infoEndpointRateLimited() throws InterruptedException {
        RestOperations restTemplate = serverRunning.getRestTemplate();
        //One Request should pass
        ResponseEntity<String> response = restTemplate.getForEntity(baseUrl + "/info", String.class);
        assertNotEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
        boolean rateLimited = false;
        ResponseEntity[] responses = new ResponseEntity[50];
        //Many Requests should hit the RL
        for (int i = 0; i <50 ; i++) {
            responses[i] = restTemplate.getForEntity(baseUrl + "/info", String.class);
        }
        for (ResponseEntity entity : responses) {
            if (HttpStatus.TOO_MANY_REQUESTS.equals(entity.getStatusCode())) {
                rateLimited = true;
                break;
            }
        }
        assertTrue(rateLimited);
        //After 1s, New Limit should be available
        Thread.sleep(1000);
        response = restTemplate.getForEntity(baseUrl + "/info", String.class);
        assertNotEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
    }

    @Test
    public void rateLimitingStatusActive() {
        webDriver.get(baseUrl + "/RateLimitingStatus");
        String pageSource = webDriver.getPageSource();

        assertThat(pageSource, containsString("\"status\" : \"ACTIVE\""));
    }
}
