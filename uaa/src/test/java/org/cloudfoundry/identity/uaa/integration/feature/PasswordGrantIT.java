package org.cloudfoundry.identity.uaa.integration.feature;

import java.security.SecureRandom;
import java.util.Arrays;

import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class PasswordGrantIT {
    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Value("${integration.test.app_url}")
    String appUrl;

    @Autowired
    RestOperations restOperations;

    @Autowired
    TestClient testClient;

    @Autowired
    TestAccounts testAccounts;

    @Before
    @After
    public void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        }catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.get(appUrl+"/j_spring_security_logout");
        webDriver.manage().deleteAllCookies();
    }

    @Test
    public void testUserLoginViaPasswordGrant() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader("cf", ""));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("grant_type", "password");
        postBody.add("username", testAccounts.getUserName());
        postBody.add("password", testAccounts.getPassword());

        ResponseEntity<Void> responseEntity = restOperations.exchange(baseUrl + "/oauth/token",
            HttpMethod.POST,
            new HttpEntity<>(postBody, headers),
            Void.class);

        Assert.assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    }

    @Test
    public void testUnverifiedUserLoginViaPasswordGrant() throws Exception {
        String userEmail = createUnverifiedUser();

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader("cf", ""));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("grant_type", "password");
        postBody.add("username", userEmail);
        postBody.add("password", "secr3T");

        try {
            restOperations.exchange(baseUrl + "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(postBody, headers),
                Void.class);
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.FORBIDDEN, e.getStatusCode());
        }

    }

    private String createUnverifiedUser() throws Exception {
        int randomInt = new SecureRandom().nextInt();

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String scimClientId = "scim" + randomInt;
        testClient.createScimClient(adminAccessToken, scimClientId);

        String scimAccessToken = testClient.getOAuthAccessToken(scimClientId, "scimsecret", "client_credentials", "scim.read scim.write password.write");

        String userEmail = "user" + randomInt + "@example.com";
        testClient.createUser(scimAccessToken, userEmail, userEmail, "secr3T", false);

        return userEmail;
    }
}