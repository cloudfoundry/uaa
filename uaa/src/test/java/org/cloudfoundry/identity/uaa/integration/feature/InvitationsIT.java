/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.integration.feature;

import com.dumbster.smtp.SimpleSmtpServer;
import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFail;
import org.cloudfoundry.identity.uaa.invitations.InvitationsRequest;
import org.cloudfoundry.identity.uaa.invitations.InvitationsResponse;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.RetryRule;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.concurrent.TimeUnit;


import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getZoneAdminToken;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.MediaType.APPLICATION_JSON;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
@ExtendWith(PollutionPreventionExtension.class)
public class InvitationsIT {

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    @Rule
    public ScreenshotOnFail screenShootRule = new ScreenshotOnFail();
    @Rule
    public RetryRule retryRule = new RetryRule(3);

    @Autowired
    WebDriver webDriver;

    @Autowired
    SimpleSmtpServer simpleSmtpServer;

    @Autowired
    TestClient testClient;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Value("${integration.test.app_url}")
    String appUrl;

    ServerRunning serverRunning = ServerRunning.isRunning();

    private String scimToken;
    private String loginToken;
    private String testInviteEmail;

    @Before
    public void setup() {
        scimToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "scim.read,scim.write,clients.admin");
        loginToken = testClient.getOAuthAccessToken("login", "loginsecret", "client_credentials", "oauth.login");
        screenShootRule.setWebDriver(webDriver);

        testInviteEmail = "testinvite@test.org";

        String userId = IntegrationTestUtils.getUserIdByField(scimToken,
                baseUrl,
                "simplesamlphp",
                "userName",
                "user_only_for_invitations_test");
        if (userId != null) {
            IntegrationTestUtils.deleteUser(scimToken, baseUrl, userId);
        }

        userId = IntegrationTestUtils.getUserIdByField(scimToken,
                baseUrl,
                "simplesamlphp",
                "userName",
                "testinvite@test.org");
        if (userId != null) {
            IntegrationTestUtils.deleteUser(scimToken, baseUrl, userId);
        }
    }

    @Before
    @After
    public void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.get(appUrl + "/j_spring_security_logout");
        webDriver.get(IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE + "/module.php/core/authenticate.php?as=example-userpass&logout");
        webDriver.manage().deleteAllCookies();

        webDriver.get("http://localhost:8080/app/");
        webDriver.manage().deleteAllCookies();
    }

    @Test
    public void invite_fails() {
        RestTemplate uaaTemplate = new RestTemplate();
        uaaTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            protected boolean hasError(HttpStatus statusCode) {
                return statusCode.is5xxServerError();
            }
        });
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(APPLICATION_JSON);
        HttpEntity<String> request = new HttpEntity<>("{\"emails\":[\"marissa@test.org\"]}", headers);
        ResponseEntity<Void> response = uaaTemplate.exchange(baseUrl + "/invite_users/?client_id=admin&redirect_uri={uri}", POST, request, Void.class, "https://www.google.com");
        assertThat(response.getStatusCode(), is(HttpStatus.UNAUTHORIZED));
    }

    @Test
    public void testInviteUserWithClientRedirect() throws Exception {
        String userEmail = "user-" + new RandomValueStringGenerator().generate() + "@example.com";
        //user doesn't exist
        performInviteUser(userEmail, false);
        //user exist
        performInviteUser(userEmail, true);
    }

    public void performInviteUser(String email, boolean isVerified) {
        webDriver.get(baseUrl + "/logout.do");
        String redirectUri = baseUrl + "/profile";
        String code = createInvitation(email, email, redirectUri, OriginKeys.UAA);
        String invitedUserId = IntegrationTestUtils.getUserIdByField(scimToken, baseUrl, OriginKeys.UAA, "email", email);
        if (isVerified) {
            ScimUser user = IntegrationTestUtils.getUser(scimToken, baseUrl, invitedUserId);
            user.setVerified(true);
            IntegrationTestUtils.updateUser(scimToken, baseUrl, user);
        }
        String currentUserId = null;
        try {
            currentUserId = IntegrationTestUtils.getUserId(scimToken, baseUrl, OriginKeys.UAA, email);
        } catch (RuntimeException ignored) {
        }
        assertEquals(invitedUserId, currentUserId);

        webDriver.get(baseUrl + "/invitations/accept?code=" + code);
        if (!isVerified) {
            assertEquals("Create your account", webDriver.findElement(By.tagName("h1")).getText());
            webDriver.findElement(By.name("password")).sendKeys("secr3T");
            webDriver.findElement(By.name("password_confirmation")).sendKeys("secr3T");
            webDriver.findElement(By.xpath("//input[@value='Create account']")).click();

            assertTrue(IntegrationTestUtils.getUser(scimToken, baseUrl, OriginKeys.UAA, email).isVerified());

            webDriver.findElement(By.name("username")).sendKeys(email);
            webDriver.findElement(By.name("password")).sendKeys("secr3T");
            webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

            Assert.assertEquals(redirectUri, webDriver.getCurrentUrl());
        } else {
            //redirect to the home page to login
            Assert.assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Welcome!"));
        }
        String acceptedUserId = IntegrationTestUtils.getUserId(scimToken, baseUrl, OriginKeys.UAA, email);
        if (currentUserId == null) {
            assertEquals(invitedUserId, acceptedUserId);
        } else {
            assertEquals(currentUserId, acceptedUserId);
        }
    }

    @Test
    public void acceptInvitation_for_samlUser() throws Exception {
        webDriver.get(baseUrl + "/logout.do");

        BaseClientDetails appClient = IntegrationTestUtils.getClient(scimToken, baseUrl, "app");
        appClient.setScope(Lists.newArrayList("cloud_controller.read", "password.write", "scim.userids", "cloud_controller.write", "openid", "organizations.acme"));
        appClient.setAutoApproveScopes(Lists.newArrayList("openid"));
        IntegrationTestUtils.updateClient(baseUrl, scimToken, appClient);

        String code = createInvitation(testInviteEmail, testInviteEmail, "http://localhost:8080/app/", "simplesamlphp");

        String invitedUserId = IntegrationTestUtils.getUserIdByField(scimToken, baseUrl, "simplesamlphp", "email", testInviteEmail);
        IntegrationTestUtils.createIdentityProvider("simplesamlphp", true, baseUrl, serverRunning);

        webDriver.get(baseUrl + "/invitations/accept?code=" + code);
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys("user_only_for_invitations_test");
        webDriver.findElement(By.name("password")).sendKeys("saml");
        WebElement loginButton = webDriver.findElement(By.xpath("//input[@value='Login']"));

        loginButton.click();

        //wait until UAA page has loaded
        webDriver.findElement(By.id("application_authorization"));
        String acceptedUsername = IntegrationTestUtils.getUsernameById(scimToken, baseUrl, invitedUserId);
        //webdriver follows redirects so we should be on the UAA authorization page
        assertEquals("user_only_for_invitations_test", acceptedUsername);

        //external users should default to not being "verified" since we can't determine this
        ScimUser user = IntegrationTestUtils.getUser(scimToken, baseUrl, invitedUserId);
        assertFalse(user.isVerified());
    }

    @Test
    public void testInsecurePasswordDisplaysErrorMessage() {
        String code = createInvitation();
        webDriver.get(baseUrl + "/invitations/accept?code=" + code);
        assertEquals("Create your account", webDriver.findElement(By.tagName("h1")).getText());

        String newPassword = new RandomValueStringGenerator(260).generate();
        webDriver.findElement(By.name("password")).sendKeys(newPassword);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(newPassword);

        webDriver.findElement(By.xpath("//input[@value='Create account']")).click();
        assertThat(webDriver.findElement(By.cssSelector(".alert-error")).getText(), containsString("Password must be no more than 255 characters in length."));
        webDriver.findElement(By.name("password"));
        webDriver.findElement(By.name("password_confirmation"));
    }

    @Test
    public void invitedOIDCUserVerified() throws Exception {
        String clientId = "invite-client" + new RandomValueStringGenerator().generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, null, "client_credentials", "scim.invite");
        clientDetails.setClientSecret("invite-client-secret");
        testClient.createClient(scimToken, clientDetails);
        String inviteToken = testClient.getOAuthAccessToken(clientId, "invite-client-secret", "client_credentials", "scim.invite");
        IntegrationTestUtils.createOidcIdentityProvider("oidc-invite-provider", "puppy-invite", baseUrl);

        RestTemplate uaaTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + inviteToken);
        headers.setContentType(APPLICATION_JSON);
        InvitationsRequest body = new InvitationsRequest();
        String[] emailList = new String[]{"marissa@test.org"};
        body.setEmails(emailList);
        HttpEntity<InvitationsRequest> request = new HttpEntity<>(body, headers);
        ResponseEntity<InvitationsResponse> response = uaaTemplate.exchange(baseUrl + "/invite_users?client_id=app&redirect_uri=" + appUrl, POST, request, InvitationsResponse.class);
        assertThat(response.getStatusCode(), is(HttpStatus.OK));

        String userId = response.getBody().getNewInvites().get(0).getUserId();
        URL inviteLink = response.getBody().getNewInvites().get(0).getInviteLink();

        webDriver.get(inviteLink.toString());
        webDriver.findElement(By.xpath("//h1[contains(text(), 'Welcome')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys("marissa");
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        ScimUser user = IntegrationTestUtils.getUser(scimToken, baseUrl, userId);
        assertTrue(user.isVerified());

        webDriver.get(IntegrationTestUtils.OIDC_ACCEPTANCE_URL + "logout.do");
        IntegrationTestUtils.deleteProvider(getZoneAdminToken(baseUrl, serverRunning), baseUrl, "uaa", "puppy-invite");
    }

    private String createInvitation() {
        String userEmail = "user" + new SecureRandom().nextInt() + "@example.com";
        return createInvitation(userEmail, userEmail, "http://localhost:8080/app/", OriginKeys.UAA);
    }

    private String createInvitation(String username, String userEmail, String redirectUri, String origin) {
        return createInvitation(baseUrl, username, userEmail, origin, redirectUri, loginToken, scimToken);
    }

    public static String createInvitation(String baseUrl, String username, String userEmail, String origin, String redirectUri, String loginToken, String scimToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + scimToken);
        RestTemplate uaaTemplate = new RestTemplate();
        ScimUser scimUser = new ScimUser();
        scimUser.setPassword("password");
        scimUser.setUserName(username);
        scimUser.setPrimaryEmail(userEmail);
        scimUser.setOrigin(origin);
        scimUser.setVerified(false);

        String userId = null;
        try {
            userId = IntegrationTestUtils.getUserIdByField(scimToken, baseUrl, origin, "email", userEmail);
            scimUser = IntegrationTestUtils.getUser(scimToken, baseUrl, userId);
        } catch (RuntimeException ignored) {
        }
        if (userId == null) {
            HttpEntity<ScimUser> request = new HttpEntity<>(scimUser, headers);
            ResponseEntity<ScimUser> response = uaaTemplate.exchange(baseUrl + "/Users", POST, request, ScimUser.class);
            if (response.getStatusCode().value()!= HttpStatus.CREATED.value()) {
                throw new IllegalStateException("Unable to create test user:"+scimUser);
            }
            userId = response.getBody().getId();
        } else {
            scimUser.setVerified(false);
            IntegrationTestUtils.updateUser(scimToken, baseUrl, scimUser);
        }

        HttpHeaders invitationHeaders = new HttpHeaders();
        invitationHeaders.add("Authorization", "Bearer " + loginToken);

        Timestamp expiry = new Timestamp(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(System.currentTimeMillis() + 24 * 3600, TimeUnit.MILLISECONDS));
        ExpiringCode expiringCode = new ExpiringCode(null, expiry, "{\"origin\":\"" + origin + "\", \"client_id\":\"app\", \"redirect_uri\":\"" + redirectUri + "\", \"user_id\":\"" + userId + "\", \"email\":\"" + userEmail + "\"}", null);
        HttpEntity<ExpiringCode> expiringCodeRequest = new HttpEntity<>(expiringCode, invitationHeaders);
        ResponseEntity<ExpiringCode> expiringCodeResponse = uaaTemplate.exchange(baseUrl + "/Codes", POST, expiringCodeRequest, ExpiringCode.class);
        expiringCode = expiringCodeResponse.getBody();
        return expiringCode.getCode();
    }
}
