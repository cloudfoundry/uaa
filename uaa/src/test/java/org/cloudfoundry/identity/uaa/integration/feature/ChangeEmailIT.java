package org.cloudfoundry.identity.uaa.integration.feature;

import com.dumbster.smtp.SimpleSmtpServer;
import com.dumbster.smtp.SmtpMessage;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.security.SecureRandom;
import java.util.Iterator;

import static org.apache.commons.lang3.StringUtils.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class ChangeEmailIT {

    @Autowired @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    SimpleSmtpServer simpleSmtpServer;

    @Autowired
    TestClient testClient;

    private String userEmail;

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

    @Before
    public void setUp() {
        int randomInt = new SecureRandom().nextInt();

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String scimClientId = "scim" + randomInt;
        testClient.createScimClient(adminAccessToken, scimClientId);

        String scimAccessToken = testClient.getOAuthAccessToken(scimClientId, "scimsecret", "client_credentials", "scim.read scim.write password.write");

        userEmail = "user" + randomInt + "@example.com";
        testClient.createUser(scimAccessToken, userEmail, userEmail, "secr3T", true);
    }

    @Test
    public void testChangeEmailWithLogout() {
        String newEmail = testChangeEmail(true);

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Welcome"));
        assertThat(webDriver.findElement(By.cssSelector(".alert-success")).getText(), containsString("Email address successfully verified. Login to access your account."));

        signIn(newEmail, "secr3T");

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));
    }

    @Test
    public void testChangeEmailWithoutLogout() {
        String newEmail = testChangeEmail(false);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Account Settings"));
        assertThat(webDriver.findElement(By.cssSelector(".alert-success")).getText(), containsString("Email address successfully verified."));
        assertThat(webDriver.findElement(By.cssSelector(".nav")).getText(), containsString(newEmail));
        assertThat(webDriver.findElement(By.cssSelector(".profile")).getText(), containsString(newEmail));
    }

    public String testChangeEmail(boolean logout) {
        signIn(userEmail, "secr3T");
        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        webDriver.get(baseUrl + "/profile");
        Assert.assertEquals(userEmail, webDriver.findElement(By.cssSelector(".profile .email")).getText());
        webDriver.findElement(By.linkText("Change Email")).click();

        Assert.assertEquals("Current Email Address: " + userEmail, webDriver.findElement(By.cssSelector(".email-display")).getText());
        String newEmail = userEmail.replace("user", "new");
        webDriver.findElement(By.name("newEmail")).sendKeys(newEmail);
        webDriver.findElement(By.xpath("//input[@value='Send Verification Link']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Instructions Sent"));
        assertEquals(receivedEmailSize + 1, simpleSmtpServer.getReceivedEmailSize());

        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();

        assertEquals(newEmail, message.getHeaderValue("To"));
        assertThat(message.getBody(), containsString("Verify your email"));

        String link = testClient.extractLink(message.getBody());
        assertFalse(contains(link, "@"));
        assertFalse(contains(link, "%40"));

        if (logout) {
            webDriver.get(baseUrl + "/logout.do");
        }

        webDriver.get(link);

        return newEmail;
    }

    @Test
    public void testChangeEmailWithClientRedirect() {
        signIn(userEmail, "secr3T");

        webDriver.get(baseUrl + "/change_email?client_id=app");

        String newEmail = userEmail.replace("user", "new");
        webDriver.findElement(By.name("newEmail")).sendKeys(newEmail);
        webDriver.findElement(By.xpath("//input[@value='Send Verification Link']")).click();

        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        String link = testClient.extractLink(message.getBody());

        webDriver.get(link);
        webDriver.findElement(By.id("authorize")).click();
        assertThat(webDriver.getCurrentUrl(), startsWith("http://localhost:8080/app/"));
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
