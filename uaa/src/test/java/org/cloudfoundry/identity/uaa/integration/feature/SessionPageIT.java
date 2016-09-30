package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.login.CurrentUserInformation;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import static org.junit.Assert.assertEquals;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
public class SessionPageIT {

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    String userId;
    String testPage;

    @Before
    public void setUp() throws UnsupportedEncodingException {
        webDriver.get(baseUrl + "logout.do");
        webDriver.manage().deleteAllCookies();
        if(userId == null) {
            doLogin();

            Cookie currentUserCookie = webDriver.manage().getCookieNamed("Current-User");
            CurrentUserInformation currentUserInformation = JsonUtils.readValue(URLDecoder.decode(currentUserCookie.getValue(), "UTF-8"), CurrentUserInformation.class);

            userId = currentUserInformation.getUserId();
            testPage = "file://" + System.getProperty("user.dir") + "/src/test/resources/session_frame_test.html#" + userId;

            webDriver.get(baseUrl + "logout.do");
            webDriver.manage().deleteAllCookies();
        }
    }

    @Test
    public void testFrameReportsUnchangedWhenSendingSameUser() throws UnsupportedEncodingException, InterruptedException {
        doLogin();

        webDriver.get(testPage);
        webDriver.findElement(By.id("sameUser")).click();

        assertMessage("unchanged");
    }

    private void assertMessage(String expected) {
        assertEquals(expected, webDriver.findElement(By.id("message")).getText());
    }

    private void doLogin() {
        webDriver.get(baseUrl + "/login");
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
    }
}
