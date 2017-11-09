package org.cloudfoundry.identity.uaa.integration;

import com.dumbster.smtp.SimpleSmtpServer;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.feature.TestClient;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class TotpEndpointIntegrationTests {

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    SimpleSmtpServer simpleSmtpServer;

    @Autowired
    TestClient testClient;

    private static final String USER_PASSWORD = "sec3Tas";


    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();
    private IdentityZone mfaZone;
    private RestTemplate adminClient;
    private String zoneUrl;
    private String username;
    private MfaProvider mfaProvider;

    @Before
    public void setup() throws Exception {
        ClientCredentialsResourceDetails adminResource = IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret");
        adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                adminResource);

        mfaZone = IntegrationTestUtils.fixtureIdentityZone("testzone1", "testzone1");
        mfaZone = IntegrationTestUtils.createZoneOrUpdateSubdomain(adminClient, baseUrl, "testzone1", "testzone1");

        zoneUrl = baseUrl.replace("localhost", mfaZone.getSubdomain() + ".localhost");

        String zoneAdminToken = IntegrationTestUtils.getZoneAdminToken(baseUrl, serverRunning, mfaZone.getId());
        username = createRandomUser();
        mfaProvider = enableMfaInZone(zoneAdminToken);
        webDriver.get(zoneUrl + "/logout.do");
    }

    @After
    public void cleanup() {
        webDriver.get(zoneUrl + "/logout.do");
        mfaZone.getConfig().getMfaConfig().setEnabled(false).setProviderName(null);
        IntegrationTestUtils.createZoneOrUpdateSubdomain(adminClient, baseUrl, mfaZone.getId(), mfaZone.getSubdomain(), mfaZone.getConfig());
    }

    @Test
    public void testQRCodeScreen() {
        performLogin(username);
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        assertThat(webDriver.findElement(By.id("qr")).getAttribute("src"), Matchers.containsString("chart.googleapis"));

        webDriver.findElement(By.id("Next")).click();
        assertEquals(zoneUrl + "/login/mfa/verify", webDriver.getCurrentUrl());
    }

    @Test
    public void testQRCodeValidation() {
        performLogin(username);
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        assertThat(webDriver.findElement(By.id("qr")).getAttribute("src"), Matchers.containsString("chart.googleapis"));

        webDriver.findElement(By.id("Next")).click();
        assertEquals(zoneUrl + "/login/mfa/verify", webDriver.getCurrentUrl());
        webDriver.findElement(By.name("code")).sendKeys("1111111111111111112222");

        webDriver.findElement(By.id("verify_code_btn")).click();
        assertEquals("Invalid QR code", webDriver.findElement(By.cssSelector("form .error-color")).getText());
    }

    @Test
    public void checkAccessForTotpPage() {
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl + "/login/mfa/register");

        assertEquals(zoneUrl + "/login", webDriver.getCurrentUrl());
    }

    @Test
    public void testDisplayMfaIssuerOnRegisterPage() {
        performLogin(username);
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        assertThat(webDriver.findElement(By.id("mfa-provider")).getText(), Matchers.containsString(mfaProvider.getName()));
    }

    private void performLogin(String username) {
        webDriver.get(zoneUrl + "/login");

        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys(USER_PASSWORD);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
    }

    private MfaProvider enableMfaInZone(String zoneAdminToken) {
        MfaProvider provider = IntegrationTestUtils.createGoogleMfaProvider(baseUrl, zoneAdminToken, MockMvcUtils.constructGoogleMfaProvider(), mfaZone.getId());
        mfaZone.getConfig().getMfaConfig().setEnabled(true).setProviderName(provider.getName());
        mfaZone = IntegrationTestUtils.createZoneOrUpdateSubdomain(adminClient, baseUrl, "testzone1", mfaZone.getSubdomain() , mfaZone.getConfig());
        return provider;
    }

    private String createRandomUser() {
        ScimUser user = new ScimUser(null, new RandomValueStringGenerator(5).generate(), "first", "last");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword(USER_PASSWORD);

        return IntegrationTestUtils.createAnotherUser(webDriver, USER_PASSWORD, simpleSmtpServer, zoneUrl, testClient);
    }

}
