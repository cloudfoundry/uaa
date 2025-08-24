package org.cloudfoundry.identity.uaa.integration.feature;

import com.dumbster.smtp.SimpleSmtpServer;
import com.dumbster.smtp.SmtpMessage;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.security.SecureRandom;
import java.util.Iterator;

import static org.apache.commons.lang3.StringUtils.contains;
import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class ChangeEmailIT {

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    UaaWebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    SimpleSmtpServer simpleSmtpServer;

    @Autowired
    TestClient testClient;

    private String userEmail;

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

    @BeforeEach
    void setUp() {
        int randomInt = new SecureRandom().nextInt();

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String scimClientId = "scim" + randomInt;
        testClient.createScimClient(adminAccessToken, scimClientId);

        String scimAccessToken = testClient.getOAuthAccessToken(scimClientId, "scimsecret", "client_credentials", "scim.read scim.write password.write");

        userEmail = "user" + randomInt + "@example.com";
        testClient.createUser(scimAccessToken, userEmail, userEmail, "secr3T", true);
    }

    @Test
    void changeEmailWithLogout() {
        String newEmail = changeEmail(true);

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Welcome");
        assertThat(webDriver.findElement(By.cssSelector(".alert-success")).getText()).contains("Email address successfully verified. Login to access your account.");

        signIn(newEmail, "secr3T");

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
    }

    @Test
    void changeEmailWithoutLogout() {
        String newEmail = changeEmail(false);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.findElement(By.cssSelector(".alert-success")).getText()).contains("Email address successfully verified.");
        assertThat(webDriver.findElement(By.cssSelector(".nav")).getText()).contains(newEmail);
        assertThat(webDriver.findElement(By.cssSelector(".profile")).getText()).contains(newEmail);
    }

    private String changeEmail(boolean logout) {
        signIn(userEmail, "secr3T");
        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.findElement(By.cssSelector(".profile .email")).getText()).isEqualTo(userEmail);
        webDriver.clickAndWait(By.linkText("Change Email"));

        assertThat(webDriver.findElement(By.cssSelector(".email-display")).getText()).isEqualTo("Current Email Address: " + userEmail);
        String newEmail = userEmail.replace("user", "new");
        webDriver.findElement(By.name("newEmail")).sendKeys(newEmail);
        webDriver.clickAndWait(By.xpath("//input[@value='Send Verification Link']"));

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Instructions Sent");
        assertThat(simpleSmtpServer.getReceivedEmailSize()).isEqualTo(receivedEmailSize + 1);

        Iterator<SmtpMessage> receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = receivedEmail.next();
        receivedEmail.remove();

        assertThat(message.getHeaderValue("To")).isEqualTo(newEmail);
        assertThat(message.getBody()).contains("Verify your email");

        String link = testClient.extractLink(message.getBody());
        assertThat(contains(link, "@")).isFalse();
        assertThat(contains(link, "%40")).isFalse();

        if (logout) {
            webDriver.get(baseUrl + "/logout.do");
        }

        webDriver.get(link);

        return newEmail;
    }

    @Test
    void changeEmailWithClientRedirect() {
        signIn(userEmail, "secr3T");

        webDriver.get(baseUrl + "/change_email?client_id=app");

        String newEmail = userEmail.replace("user", "new");
        webDriver.findElement(By.name("newEmail")).sendKeys(newEmail);
        webDriver.clickAndWait(By.xpath("//input[@value='Send Verification Link']"));

        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        String link = testClient.extractLink(message.getBody());

        webDriver.get(link);
        //simulate redirect to app and back
        webDriver.get(baseUrl + "/oauth/authorize?client_id=app&redirect_uri=http://localhost:8080/app/&response_type=code&state=3e5u7U");
        webDriver.clickAndWait(By.id("authorize"));
        assertThat(webDriver.getCurrentUrl()).startsWith("http://localhost:8080/app/?code=");
    }

    private void signIn(String userName, String password) {
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/login");
        webDriver.findElement(By.name("username")).sendKeys(userName);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
    }
}
