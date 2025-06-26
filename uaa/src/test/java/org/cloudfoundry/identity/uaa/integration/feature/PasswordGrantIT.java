package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class PasswordGrantIT {
    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    RestOperations restOperations;

    @Autowired
    TestClient testClient;

    @Autowired
    TestAccounts testAccounts;

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
    void userLoginViaPasswordGrant() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader("cf", ""));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("grant_type", "password");
        postBody.add("username", testAccounts.getUserName());
        postBody.add("password", testAccounts.getPassword());

        ResponseEntity<Void> responseEntity = restOperations.exchange(baseUrl + "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(postBody, headers),
                Void.class);

        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void userLoginViaPasswordGrantLoginHintUaa() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
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

        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void userLoginViaPasswordGrantLoginHintUaaDoubleEncoded() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader("cf", ""));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("grant_type", "password");
        postBody.add("username", testAccounts.getUserName());
        postBody.add("password", testAccounts.getPassword());
        postBody.add("login_hint", URLEncoder.encode("{\"origin\":\"uaa\"}", StandardCharsets.UTF_8));

        ResponseEntity<Void> responseEntity = restOperations.exchange(baseUrl + "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(postBody, headers),
                Void.class);

        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void userLoginViaPasswordGrantLoginHintOidc() throws Exception {
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        try {
            createOidcProvider(clientCredentialsToken);

            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader("cf", ""));

            LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
            postBody.add("grant_type", "password");
            postBody.add("username", testAccounts.getUserName());
            postBody.add("password", testAccounts.getPassword());
            postBody.add("login_hint", "{\"origin\":\"puppy\"}");

            ResponseEntity<Void> responseEntity = restOperations.exchange(baseUrl + "/oauth/token",
                    HttpMethod.POST,
                    new HttpEntity<>(postBody, headers),
                    Void.class);

            assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        } finally {
            IntegrationTestUtils.deleteProvider(clientCredentialsToken, baseUrl, "uaa", "puppy");
        }
    }

    @Test
    void userDataChangedOnPwGrant() throws Exception {
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        try {
            createOidcProvider(clientCredentialsToken);

            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader("cf", ""));

            LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
            postBody.add("grant_type", "password");
            postBody.add("response_type", "token");
            postBody.add("username", testAccounts.getUserName());
            postBody.add("password", testAccounts.getPassword());
            postBody.add("login_hint", "{\"origin\":\"puppy\"}");

            // do a password grant to create the puppy user
            restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(postBody, headers), String.class);

            // get the uaa user in order to update it (use case: IDP user has changed)
            ScimUser user = IntegrationTestUtils.getUser(clientCredentialsToken, baseUrl, "uaa", "marissa");
            String oldMail = user.getEmails().getFirst().getValue();
            String newMail = oldMail + "-new";

            // verify that the puppy user has the correct family and given name
            ScimUser puppyUser = IntegrationTestUtils.getUser(clientCredentialsToken, baseUrl, "puppy", "marissa");
            assertThat(puppyUser.getFamilyName()).isEqualTo(oldMail);
            assertThat(puppyUser.getGivenName()).isEqualTo(oldMail);

            // update uaa user email
            user.getEmails().getFirst().setValue(newMail);
            IntegrationTestUtils.updateUser(clientCredentialsToken, baseUrl, user);

            // do password grant again to provision user changes to user with origin "puppy"
            restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(postBody, headers), String.class);
            // verify that given and family have been updated accordingly
            puppyUser = IntegrationTestUtils.getUser(clientCredentialsToken, baseUrl, "puppy", "marissa");
            assertThat(puppyUser.getFamilyName()).isEqualTo(newMail);
            assertThat(puppyUser.getGivenName()).isEqualTo(newMail);

            // get new user instance to get current version count and revert the update from above
            user = IntegrationTestUtils.getUser(clientCredentialsToken, baseUrl, "uaa", "marissa");
            user.getEmails().getFirst().setValue(oldMail);
            IntegrationTestUtils.updateUser(clientCredentialsToken, baseUrl, user);

            // verify that the email is the old one
            user = IntegrationTestUtils.getUser(clientCredentialsToken, baseUrl, "uaa", "marissa");
            assertThat(user.getEmails().getFirst().getValue()).isEqualTo(oldMail);
        } finally {
            IntegrationTestUtils.deleteProvider(clientCredentialsToken, baseUrl, "uaa", "puppy");
        }

    }

    @Test
    void userLoginViaPasswordGrantLoginHintOidcFails() throws Exception {
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        try {
            createOidcProvider(clientCredentialsToken);

            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader("cf", ""));

            LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
            postBody.add("grant_type", "password");
            postBody.add("username", testAccounts.getUserName());
            postBody.add("password", "invalidPassword");
            postBody.add("login_hint", "{\"origin\":\"puppy\"}");

            try {
                ResponseEntity<Void> responseEntity = restOperations.exchange(baseUrl + "/oauth/token",
                        HttpMethod.POST,
                        new HttpEntity<>(postBody, headers),
                        Void.class);
            } catch (HttpClientErrorException e) {
                assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            }
            //Check Audit events?

        } finally {
            IntegrationTestUtils.deleteProvider(clientCredentialsToken, baseUrl, "uaa", "puppy");
        }
    }

    @Test
    void userLoginViaPasswordGrantInvalidLoginHint() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
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
            fail("");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Test
    void unverifiedUserLoginViaPasswordGrant() throws Exception {
        String userEmail = createUnverifiedUser();

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
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
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }

    }

    private String createUnverifiedUser() {
        int randomInt = new SecureRandom().nextInt();

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String scimClientId = "scim" + randomInt;
        testClient.createScimClient(adminAccessToken, scimClientId);

        String scimAccessToken = testClient.getOAuthAccessToken(scimClientId, "scimsecret", "client_credentials", "scim.read scim.write password.write");

        String userEmail = "user" + randomInt + "@example.com";
        testClient.createUser(scimAccessToken, userEmail, userEmail, "secr3T", false);

        return userEmail;
    }

    private void createOidcProvider(String clientCredentialsToken) throws MalformedURLException {
        IdentityProvider identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.setClientAuthInBody(false);
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.addAttributeMapping("given_name", "email");
        config.addAttributeMapping("family_name", "email");
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
    }
}