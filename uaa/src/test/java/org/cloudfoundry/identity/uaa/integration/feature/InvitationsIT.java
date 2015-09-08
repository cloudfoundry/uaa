/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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
import com.dumbster.smtp.SmtpMessage;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class InvitationsIT {

    @Autowired
    TestAccounts testAccounts;

    @Autowired @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Autowired
    SimpleSmtpServer simpleSmtpServer;

    @Autowired
    TestClient testClient;

    @Value("${integration.test.uaa_url}")
    String uaaUrl;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Value("${integration.test.app_url}")
    String appUrl;

    private String scimToken;
    private String loginToken;

    @Before
    public void setupTokens() throws Exception {
        scimToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "scim.read");
        loginToken = testClient.getOAuthAccessToken("login", "loginsecret", "client_credentials", "password.write,scim.write");
    }

    @After
    public void doLogout() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
    }


    @Test
    public void testSendInvite() throws Exception {
        int randomInt = new SecureRandom().nextInt();
        String userEmail = "user" + randomInt + "@example.com";
        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        signIn(testAccounts.getUserName(), testAccounts.getPassword());

        webDriver.findElement(By.linkText("Invite Users")).click();
        assertEquals("Send an invite", webDriver.findElement(By.tagName("h1")).getText());

        webDriver.findElement(By.name("client_id"));
        webDriver.findElement(By.name("redirect_uri"));
        webDriver.findElement(By.name("email")).sendKeys(userEmail);
        webDriver.findElement(By.xpath("//input[@value='Send invite']")).click();

        assertEquals("Invite sent", webDriver.findElement(By.tagName("h1")).getText());

        assertEquals(receivedEmailSize + 1, simpleSmtpServer.getReceivedEmailSize());
        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        assertEquals(userEmail, message.getHeaderValue("To"));
        assertThat(message.getBody(), containsString("Accept Invite"));

        String link = testClient.extractLink(message.getBody());
        assertTrue(link.contains("/invitations/accept"));
        webDriver.get(link);

        assertEquals("Create your account", webDriver.findElement(By.tagName("h1")).getText());

        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("secr3T");

        webDriver.findElement(By.xpath("//input[@value='Create account']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));

        webDriver.findElement(By.xpath("//*[text()='"+userEmail+"']")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();

        webDriver.findElement(By.name("username")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));
    }

    @Test
    public void test_LDAP_User_Invite_and_Accept() {
        Assume.assumeTrue("Ldap profile must be enabled for this test.", System.getProperty("spring.profiles.active", "default").contains(Origin.LDAP));
        perform_LDAP_User_Invite_and_Accept();
        //we should be able to invite the same user multiple time
        perform_LDAP_User_Invite_and_Accept();
        //and invite a user that has already been invited
        perform_LDAP_User_Invite_and_Accept();
    }
    public void perform_LDAP_User_Invite_and_Accept() {
        webDriver.get(baseUrl + "/logout.do");
        String username = "marissa5";
        String email = username+"@test.com";
        String code = generateCode(username, email, "");
        String invitedUserId = IntegrationTestUtils.getUserId(scimToken, baseUrl, Origin.UNKNOWN, username);
        String currentUserId = null;
        try {
            currentUserId = IntegrationTestUtils.getUserId(scimToken, baseUrl, Origin.LDAP, username);
        } catch (RuntimeException x) {}
        assertNotEquals(invitedUserId, currentUserId);
        webDriver.get(baseUrl + "/invitations/accept?code=" + code);
        assertEquals("Create your account", webDriver.findElement(By.tagName("h1")).getText());
        webDriver.findElement(By.name("enterprise_username")).sendKeys(username);
        webDriver.findElement(By.name("enterprise_password")).sendKeys("ldap5");
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();
        Assert.assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));
        String acceptedUserId = IntegrationTestUtils.getUserId(scimToken, baseUrl, Origin.LDAP, username);
        if (currentUserId==null) {
            assertEquals(invitedUserId, acceptedUserId);
        } else {
            assertEquals(currentUserId, acceptedUserId);
        }
    }

    @Test
    public void test_SAML_User_Invite_and_Accept() {
    }

    @Test
    public void test_SAML_User_Invite_Redirect_and_Accept() {

    }

    @Test
    public void testInviteUser() throws Exception {
        String userEmail = "user-" + new RandomValueStringGenerator().generate() + "@example.com";
        //user doesn't exist
        performInviteUser(userEmail);
        //user exist, invitation doesn't exist
        performInviteUser(userEmail);
        //user exists, invitation exists
        performInviteUser(userEmail);
    }
    public void performInviteUser(String email) throws Exception {
        webDriver.get(baseUrl + "/logout.do");
        String code = generateCode(email, email, "");

        String invitedUserId = IntegrationTestUtils.getUserId(scimToken, baseUrl, Origin.UNKNOWN, email);
        String currentUserId = null;
        try {
            currentUserId = IntegrationTestUtils.getUserId(scimToken, baseUrl, Origin.UAA, email);
        } catch (RuntimeException x) {}
        assertNotEquals(invitedUserId, currentUserId);

        webDriver.get(baseUrl + "/invitations/accept?code=" + code);
        assertEquals("Create your account", webDriver.findElement(By.tagName("h1")).getText());

        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("secr3T");

        webDriver.findElement(By.xpath("//input[@value='Create account']")).click();
        Assert.assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));

        String acceptedUserId = IntegrationTestUtils.getUserId(scimToken, baseUrl, Origin.UAA, email);
        if (currentUserId==null) {
            assertEquals(invitedUserId, acceptedUserId);
        } else {
            assertEquals(currentUserId, acceptedUserId);
        }
    }

    @Test
    public void testInsecurePasswordDisplaysErrorMessage() throws Exception {
        String code = generateCode();
        webDriver.get(baseUrl + "/invitations/accept?code=" + code);
        assertEquals("Create your account", webDriver.findElement(By.tagName("h1")).getText());

        String newPassword = new RandomValueStringGenerator(260).generate();
        webDriver.findElement(By.name("password")).sendKeys(newPassword);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(newPassword);

        webDriver.findElement(By.xpath("//input[@value='Create account']")).click();
        assertThat(webDriver.findElement(By.cssSelector(".alert-error")).getText(), containsString("Password must be no more than 255 characters in length."));
    }

    private String generateCode() {
        String userEmail = "user" + new SecureRandom().nextInt() + "@example.com";
        return generateCode(userEmail, userEmail, "http://localhost:8080/app/");
    }
    private String generateCode(String username, String userEmail, String redirectUri) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + loginToken);
        RestTemplate uaaTemplate = new RestTemplate();
        ScimUser scimUser = new ScimUser();
        scimUser.setUserName(username);
        scimUser.setPrimaryEmail(userEmail);
        scimUser.setOrigin(Origin.UNKNOWN);

        String userId = null;
        try {
            userId = IntegrationTestUtils.getUserId(scimToken, baseUrl, Origin.UNKNOWN, username);
        } catch (RuntimeException x) {
        }
        if (userId==null) {
            HttpEntity<ScimUser> request = new HttpEntity<>(scimUser, headers);
            ResponseEntity<ScimUser> response = uaaTemplate.exchange(uaaUrl + "/Users", HttpMethod.POST, request, ScimUser.class);
            userId = response.getBody().getId();
        }

        Timestamp expiry = new Timestamp(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(System.currentTimeMillis() + 24 * 3600, TimeUnit.MILLISECONDS));
        ExpiringCode expiringCode = new ExpiringCode(null, expiry, "{\"client_id\":\"app\", \"redirect_uri\":\""+redirectUri+"\", \"user_id\":\"" + userId + "\", \"email\":\""+userEmail+"\"}");
        HttpEntity<ExpiringCode> expiringCodeRequest = new HttpEntity<>(expiringCode, headers);
        ResponseEntity<ExpiringCode> expiringCodeResponse = uaaTemplate.exchange(uaaUrl + "/Codes", HttpMethod.POST, expiringCodeRequest, ExpiringCode.class);
        expiringCode = expiringCodeResponse.getBody();
        return expiringCode.getCode();
    }




    private void signIn(String userName, String password) {
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/login");
        webDriver.findElement(By.name("username")).sendKeys(userName);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));
    }
}
