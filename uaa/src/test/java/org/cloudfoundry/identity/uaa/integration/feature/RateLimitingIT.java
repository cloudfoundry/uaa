package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestOperations;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class RateLimitingIT {

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    @Autowired
    RestOperations restOperations;

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @BeforeEach
    @AfterEach
    void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }

    @Test
    void infoEndpointRateLimited() throws InterruptedException {
        RestOperations restTemplate = serverRunning.getRestTemplate();
        //One Request should pass
        ResponseEntity<String> response = restTemplate.getForEntity(baseUrl + "/info", String.class);
        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        boolean rateLimited = false;
        int infoLimit = 20;
        int requestCount = 50;
        //Limit on /info is set to 20
        List<ResponseEntity> responses = new ArrayList<>(requestCount);
        //Many Requests should hit the RL
        IntStream.range(0, requestCount).forEach(x -> responses.add(restTemplate.getForEntity(baseUrl + "/info", String.class)));
        //Check numbers
        long limits = responses.stream().filter(s -> HttpStatus.TOO_MANY_REQUESTS.equals(s.getStatusCode())).count();
        long oKs = responses.stream().filter(s -> HttpStatus.OK.equals(s.getStatusCode())).count();
        assertThat(limits + oKs).isEqualTo(requestCount);
        //Expect limited count around expected ones, more limited then with OK and check with tolerance of 2 that only expected limits are done
        if (limits > oKs && limits > (infoLimit - 2) && limits < (requestCount - infoLimit + 2)) {
            rateLimited = true;
        }
        assertThat(rateLimited).as("Rate limit counters are not as expected. Request: " + requestCount + ", Limit: " + infoLimit + ", blocked: " + limits
                + ", allowed: " + oKs).isTrue();
        //After 1s, New Limit should be available
        TimeUnit.SECONDS.sleep(1);
        response = restTemplate.getForEntity(baseUrl + "/info", String.class);
        assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void rateLimitingStatusActive() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader(testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret()));

        ResponseEntity<String> responseEntity = restOperations.exchange(baseUrl + "/RateLimitingStatus",
                HttpMethod.GET,
                new HttpEntity<>(new LinkedMultiValueMap<>(), headers),
                String.class);

        assertThat(responseEntity).isNotNull();
        assertThat(responseEntity.getBody()).contains("\"status\" : \"ACTIVE\"");
    }
}
