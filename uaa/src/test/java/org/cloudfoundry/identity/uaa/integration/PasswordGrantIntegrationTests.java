package org.cloudfoundry.identity.uaa.integration;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.test.HasStatusCode.hasStatusCode;
import static org.junit.Assert.assertEquals;

@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
public class PasswordGrantIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testUserLoginViaPasswordGrant() throws Exception {
        ResponseEntity<Void> responseEntity = makePasswordGrantRequest(testAccounts.getUserName(), testAccounts.getPassword());

        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    }

    @Test
    public void testUnverifiedUserLoginViaPasswordGrant() throws Exception {
        ScimUser unverifiedUser = createUnverifiedUser();

        expectedException.expect(HttpClientErrorException.class);
        expectedException.expect(hasStatusCode(HttpStatus.FORBIDDEN));

        makePasswordGrantRequest(unverifiedUser.getUserName(), unverifiedUser.getPassword());
    }

    private ScimUser createUnverifiedUser() throws Exception {
        int randomInt = new SecureRandom().nextInt();
        String userName = "bob-" + randomInt;
        String userEmail = userName + "@example.com";

        RestOperations restTemplate = serverRunning.getRestTemplate();

        ScimUser user = new ScimUser();
        user.setUserName(userName);
        user.setPassword("secret");
        user.addEmail(userEmail);

        ResponseEntity<ScimUser> result = restTemplate.postForEntity(serverRunning.getUrl("/Users"), user, ScimUser.class);
        assertEquals(HttpStatus.CREATED, result.getStatusCode());

        return user;
    }

    private ResponseEntity<Void> makePasswordGrantRequest(String userName, String password) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", testAccounts.getAuthorizationHeader("cf", ""));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("username", userName);
        params.add("password", password);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        return new RestTemplate().postForEntity(serverRunning.getAccessTokenUri(), request, Void.class);
    }
}
