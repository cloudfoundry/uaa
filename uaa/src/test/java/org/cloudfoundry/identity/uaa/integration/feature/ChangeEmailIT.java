package org.cloudfoundry.identity.uaa.integration.feature;

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.GreenMailUtil;
import jakarta.mail.internet.MimeMessage;
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
    GreenMail greenMail;

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
    void changeEmailWithLogout() throws Exception {
        String newEmail = changeEmail(true);

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Welcome");
        assertThat(webDriver.findElement(By.cssSelector(".alert-success")).getText()).contains("Email address successfully verified. Login to access your account.");

        signIn(newEmail, "secr3T");

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
    }

    @Test
    void changeEmailWithoutLogout() throws Exception {
        String newEmail = changeEmail(false);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.findElement(By.cssSelector(".alert-success")).getText()).contains("Email address successfully verified.");
        assertThat(webDriver.findElement(By.cssSelector(".nav")).getText()).contains(newEmail);
        assertThat(webDriver.findElement(By.cssSelector(".profile")).getText()).contains(newEmail);
    }

    private String changeEmail(boolean logout) throws Exception {
        signIn(userEmail, "secr3T");
        int receivedEmailSize = greenMail.getReceivedMessages().length;

        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.findElement(By.cssSelector(".profile .email")).getText()).isEqualTo(userEmail);
        webDriver.clickAndWait(By.linkText("Change Email"));

        assertThat(webDriver.findElement(By.cssSelector(".email-display")).getText()).isEqualTo("Current Email Address: " + userEmail);
        String newEmail = userEmail.replace("user", "new");
        webDriver.findElement(By.name("newEmail")).sendKeys(newEmail);
        webDriver.clickAndWait(By.xpath("//input[@value='Send Verification Link']"));

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Instructions Sent");
        greenMail.waitForIncomingEmail(5000, receivedEmailSize + 1);
        assertThat(greenMail.getReceivedMessages()).hasSize(receivedEmailSize + 1);

        MimeMessage message = greenMail.getReceivedMessages()[receivedEmailSize];

        assertThat(message.getHeader("To")[0]).isEqualTo(newEmail);
        assertThat(GreenMailUtil.getBody(message)).contains("Verify your email");

        String link = testClient.extractLink(GreenMailUtil.getBody(message));
        assertThat(contains(link, "@")).isFalse();
        assertThat(contains(link, "%40")).isFalse();

        if (logout) {
            webDriver.get(baseUrl + "/logout.do");
        }

        webDriver.get(link);

        return newEmail;
    }

    @Test
    void changeEmailWithClientRedirect() throws Exception {
        signIn(userEmail, "secr3T");

        webDriver.get(baseUrl + "/change_email?client_id=app");

        int beforeCount = greenMail.getReceivedMessages().length;
        String newEmail = userEmail.replace("user", "new");
        webDriver.findElement(By.name("newEmail")).sendKeys(newEmail);
        webDriver.clickAndWait(By.xpath("//input[@value='Send Verification Link']"));

        greenMail.waitForIncomingEmail(5000, beforeCount + 1);
        MimeMessage message = greenMail.getReceivedMessages()[beforeCount];
        String link = testClient.extractLink(GreenMailUtil.getBody(message));

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
