package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
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

import java.net.URL;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.junit.Assert.fail;

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
    public void testUserLoginViaPasswordGrantLoginHintUaa() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader("cf", ""));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("grant_type", "password");
        postBody.add("username", testAccounts.getUserName());
        postBody.add("password", testAccounts.getPassword());
        postBody.add("login_hint", "{\"origin\":\"uaa\"}");

        ResponseEntity<Void> responseEntity = restOperations.exchange(baseUrl + "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(postBody, headers),
                Void.class);

        Assert.assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    }

    @Test
    public void testUserLoginViaPasswordGrantLoginHintUaaDoubleEncoded() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader("cf", ""));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("grant_type", "password");
        postBody.add("username", testAccounts.getUserName());
        postBody.add("password", testAccounts.getPassword());
        postBody.add("login_hint", URLEncoder.encode("{\"origin\":\"uaa\"}", "utf-8"));

        ResponseEntity<Void> responseEntity = restOperations.exchange(baseUrl + "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(postBody, headers),
                Void.class);

        Assert.assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    }

    @Test
    public void testUserLoginViaPasswordGrantLoginHintOidc() throws Exception {
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        try {
            IdentityProvider identityProvider = new IdentityProvider<>();
            identityProvider.setName("my oidc provider");
            identityProvider.setIdentityZoneId(OriginKeys.UAA);
            OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
            config.setClientAuthInBody(false);
            config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
            config.addAttributeMapping("given_name", "user_name");
            config.addAttributeMapping("user.attribute." + "the_client_id", "cid");
            config.addAttributeMapping("external_groups", "scope");

            config.setStoreCustomAttributes(true);

            config.addWhiteListedGroup("*");

            config.setAuthUrl(new URL(baseUrl + "/oauth/authorize"));
            config.setTokenUrl(new URL(baseUrl + "/oauth/token"));
            config.setTokenKeyUrl(new URL(baseUrl + "/token_key"));
            config.setIssuer(baseUrl + "/oauth/token");
            config.setUserInfoUrl(new URL(baseUrl + "/userinfo"));

            config.setShowLinkText(true);
            config.setLinkText("My OIDC Provider");
            config.setSkipSslValidation(true);
            config.setRelyingPartyId("identity");
            config.setRelyingPartySecret("identitysecret");
            config.setPasswordGrantEnabled(true);
            List<String> requestedScopes = new ArrayList<>();
            requestedScopes.add("openid");
            requestedScopes.add("cloud_controller.read");
            config.setScopes(requestedScopes);
            identityProvider.setConfig(config);
            identityProvider.setOriginKey("puppy");
            identityProvider.setIdentityZoneId("uaa");
            IntegrationTestUtils.createOrUpdateProvider(clientCredentialsToken, baseUrl, identityProvider);

            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
            headers.add("Authorization", ((UaaTestAccounts)testAccounts).getAuthorizationHeader("cf", ""));

            LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
            postBody.add("grant_type", "password");
            postBody.add("username", testAccounts.getUserName());
            postBody.add("password", testAccounts.getPassword());
            postBody.add("login_hint", "{\"origin\":\"puppy\"}");

            ResponseEntity<Void> responseEntity = restOperations.exchange(baseUrl + "/oauth/token",
                    HttpMethod.POST,
                    new HttpEntity<>(postBody, headers),
                    Void.class);

            Assert.assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteProvider(clientCredentialsToken, baseUrl, "uaa", "puppy");
        }
    }

    @Test
    public void testUserLoginViaPasswordGrantInvalidLoginHint() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader("cf", ""));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("grant_type", "password");
        postBody.add("username", testAccounts.getUserName());
        postBody.add("password", testAccounts.getPassword());
        postBody.add("login_hint", "{\"origin\":\"invalid\"}");

        try {
            ResponseEntity<Void> responseEntity = restOperations.exchange(baseUrl + "/oauth/token",
                    HttpMethod.POST,
                    new HttpEntity<>(postBody, headers),
                    Void.class);
            fail();
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
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