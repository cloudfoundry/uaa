package org.cloudfoundry.identity.uaa.integration;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.feature.TestClient;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;

import com.dumbster.smtp.SimpleSmtpServer;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import org.junit.After;
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
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class TotpMfaEndpointIntegrationTests {

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

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

    private IdentityZone mfaZone;
    private RestTemplate adminClient;
    private String zoneUrl;
    private String username;
    private MfaProvider mfaProvider;
    private String zoneAdminToken;
    private String adminAccessToken;
    private ScimUser user;

    @Before
    public void setup() throws Exception {
        ClientCredentialsResourceDetails adminResource = IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret");
        adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                adminResource);

        mfaZone = IntegrationTestUtils.createZoneOrUpdateSubdomain(adminClient, baseUrl, "testzone1", "testzone1", null);

        zoneUrl = baseUrl.replace("localhost", mfaZone.getSubdomain() + ".localhost");
        adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "uaa.admin");
        zoneAdminToken = IntegrationTestUtils.getZoneAdminToken(baseUrl, serverRunning, mfaZone.getId());
        user = createRandomUser();
        username = user.getUserName();
        mfaProvider = enableMfaInZone(zoneAdminToken);
        webDriver.get(zoneUrl + "/logout.do");
    }

    @After
    public void cleanup() {
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get(baseUrl + "/logout.do");
        webDriver.manage().deleteAllCookies();
        mfaZone.getConfig().getMfaConfig().setEnabled(false).setProviderName(null);
        IntegrationTestUtils.createZoneOrUpdateSubdomain(adminClient, baseUrl, mfaZone.getId(), mfaZone.getSubdomain(), mfaZone.getConfig());
    }

    @Test
    public void testQRCodeScreen() throws Exception {
        performLogin(username);
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        String imageSrc = webDriver.findElement(By.id("qr")).getAttribute("src");

        String secretKey = getSecretFromQrImageString(imageSrc);

        webDriver.findElement(By.id("Next")).click();
        verifyCodeOnRegistration(secretKey, "/");
    }

    @Test
    public void force_password_happens_after_MFA() throws Exception {
        IntegrationTestUtils.updateUserToForcePasswordChange(
            getRestTemplate(),
            baseUrl,
            adminAccessToken,
            user.getId(),
            mfaZone.getId()
        );

        performLogin(username);
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        String imageSrc = webDriver.findElement(By.id("qr")).getAttribute("src");

        String secretKey = getSecretFromQrImageString(imageSrc);

        webDriver.findElement(By.id("Next")).click();
        verifyCodeOnRegistration(secretKey, "/force_password_change");


    }

    @Test
    public void testQRCodeScreenAfterRegistrationDeletion() throws Exception {
        // register mfa for user and logout
        testQRCodeScreen();
        webDriver.get(zoneUrl + "/logout.do");

        // retrieve user id and delete mfa registration
        RestTemplate client = getRestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + zoneAdminToken);
        headers.add("X-Identity-Zone-Id", mfaZone.getId());
        headers.add("Content-Type", "application/json");
        Map<String, String> uriParams = new HashMap<>();
        uriParams.put("filter","userName eq \""+username+"\"");
        ResponseEntity<Map> exchange = client.exchange(serverRunning.getUrl("/Users?attributes=id&filter={filter}"), HttpMethod.GET, new HttpEntity<Void>(
            headers), Map.class, uriParams);
        String userId = (String) ((Map)((java.util.List) exchange.getBody().get("resources")).get(0)).get("id");

        client.exchange(serverRunning.getUrl("/Users/{userId}/mfa"), HttpMethod.DELETE, new HttpEntity<Void>(
            headers), Map.class, userId);

        // user login should end up at mfa registration page
        performLogin(username);
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());
    }

    private RestTemplate getRestTemplate() {
        RestTemplate client = (RestTemplate) serverRunning.getRestTemplate();
        client.setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
            }
        });
        return client;
    }

    @Test
    public void testMfaRegisterPageWithoutLoggingIn() {
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl + "/login/mfa/register");
        assertEquals(zoneUrl + "/login", webDriver.getCurrentUrl());
    }

    @Test
    public void testMfaVerifyPageWithoutLoggingIn() {
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl + "/login/mfa/verify");
        assertEquals(zoneUrl + "/login", webDriver.getCurrentUrl());
    }

    private String qrCodeText(String dataUrl) throws Exception {
        QRCodeReader reader = new QRCodeReader();
        String[] rawSplit = dataUrl.split(",");
        assertEquals("data:image/png;base64", rawSplit[0]);
        byte[] decodedByte = Base64.getDecoder().decode(rawSplit[1]);
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(decodedByte));
        BufferedImageLuminanceSource source = new BufferedImageLuminanceSource(image);
        Map<DecodeHintType, Object> hintMap = new HashMap<>();
        hintMap.put(DecodeHintType.PURE_BARCODE, true);

        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
        return reader.decode(bitmap, hintMap).getText();
    }

    @Test
    public void testQRCodeValidation() {
        performLogin(username);
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        webDriver.findElement(By.id("Next")).click();
        assertEquals(zoneUrl + "/login/mfa/verify", webDriver.getCurrentUrl());
        webDriver.findElement(By.name("code")).sendKeys("1111111111111111112222");

        webDriver.findElement(By.id("verify_code_btn")).click();
        assertEquals("Incorrect code, please try again.", webDriver.findElement(By.cssSelector("form .error-color")).getText());
    }

    @Test
    public void checkAccessForTotpPage() {
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get(zoneUrl + "/login/mfa/register");
        assertEquals(zoneUrl + "/login", webDriver.getCurrentUrl());
    }

    @Test
    public void testDisplayIdentityZoneNameOnRegisterPage() {
        performLogin(username);
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        assertEquals(webDriver.findElement(By.id("mfa-identity-zone")).getText(), mfaZone.getName());
    }

    @Test
    public void testDisplayIdentityZoneNameOnVerifyPage() {
        performLogin(username);
        webDriver.findElement(By.id("Next")).click();

        assertEquals(zoneUrl + "/login/mfa/verify", webDriver.getCurrentUrl());
        assertEquals(webDriver.findElement(By.id("mfa-identity-zone")).getText(), mfaZone.getName());

        webDriver.findElement(By.id("verify_code_btn")).click();
        assertEquals(webDriver.findElement(By.id("mfa-identity-zone")).getText(), mfaZone.getName());
    }

    @Test
    public void testManualMfaRegistrationFlow() {
        performLogin(username);
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        webDriver.findElement(By.linkText("manual setup instructions")).click();

        assertEquals(zoneUrl + "/login/mfa/manual", webDriver.getCurrentUrl());

        String key = webDriver.findElement(By.id("key")).getText();
        String account = webDriver.findElement(By.id("account")).getText();
        assertFalse("secret not found", key.isEmpty());
        assertFalse("account not found", account.isEmpty());

        webDriver.findElement(By.id("Next")).click();
        assertEquals(zoneUrl + "/login/mfa/verify", webDriver.getCurrentUrl());

        verifyCodeOnRegistration(key, "/");
    }

    private void verifyCodeOnRegistration(String key, String expectedUrlPath) {
        GoogleAuthenticator authenticator = new GoogleAuthenticator(new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder().build());
        int verificationCode = authenticator.getTotpPassword(key);
        webDriver.findElement(By.name("code")).sendKeys(Integer.toString(verificationCode));
        webDriver.findElement(By.cssSelector("form button")).click();

        assertEquals(zoneUrl + expectedUrlPath, webDriver.getCurrentUrl());
    }

    @Test
    public void testQRCodeScreen_ClickManualAndReturn() throws Exception{
        performLogin(username);
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        webDriver.findElement(By.linkText("manual setup instructions")).click();
        assertEquals(zoneUrl + "/login/mfa/manual", webDriver.getCurrentUrl());

        webDriver.findElement(By.id("Back")).click();
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        String imageSrc = webDriver.findElement(By.id("qr")).getAttribute("src");

        String secretKey = getSecretFromQrImageString(imageSrc);

        webDriver.findElement(By.id("Next")).click();
        verifyCodeOnRegistration(secretKey, "/");
    }

    @Test
    public void testManualMfaRegistrationFlow_ClickBackAndManual() {
        performLogin(username);
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        webDriver.findElement(By.linkText("manual setup instructions")).click();
        assertEquals(zoneUrl + "/login/mfa/manual", webDriver.getCurrentUrl());

        webDriver.findElement(By.id("Back")).click();
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        webDriver.findElement(By.linkText("manual setup instructions")).click();
        assertEquals(zoneUrl + "/login/mfa/manual", webDriver.getCurrentUrl());

        String key = webDriver.findElement(By.id("key")).getText();
        String account = webDriver.findElement(By.id("account")).getText();
        assertFalse("secret not found", key.isEmpty());
        assertFalse("account not found", account.isEmpty());

        webDriver.findElement(By.id("Next")).click();
        assertEquals(zoneUrl + "/login/mfa/verify", webDriver.getCurrentUrl());

        verifyCodeOnRegistration(key, "/");
    }

    @Test
    public void testQRCodeScreen_ClickManualClickNextClickBack() throws Exception{
        performLogin(username);
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        webDriver.findElement(By.linkText("manual setup instructions")).click();
        assertEquals(zoneUrl + "/login/mfa/manual", webDriver.getCurrentUrl());

        webDriver.findElement(By.id("Next")).click();
        assertEquals(zoneUrl + "/login/mfa/verify", webDriver.getCurrentUrl());

        webDriver.findElement(By.id("Back")).click();
        assertEquals(zoneUrl + "/login/mfa/register", webDriver.getCurrentUrl());

        String imageSrc = webDriver.findElement(By.id("qr")).getAttribute("src");

        String secretKey = getSecretFromQrImageString(imageSrc);

        assertFalse("secret not found", secretKey.isEmpty());

        webDriver.findElement(By.id("Next")).click();
        verifyCodeOnRegistration(secretKey, "/");
    }

    private String getSecretFromQrImageString(String imageSrc) throws Exception {
        String[] qparams = qrCodeText(imageSrc).split("\\?")[1].split("&");
        for(String param : qparams) {
            if(param.contains("issuer=")) {
                assertEquals("issuer=" + mfaProvider.getConfig().getIssuer(), URLDecoder.decode(param, StandardCharsets.UTF_8));
                break;
            }
        }
        String secretKey = "";
        for(String param: qparams) {
            String[] keyVal = param.split("=");
            if(keyVal[0].equals("secret")) {
                secretKey = keyVal[1];
                break;
            }
        }
        return secretKey;
    }

    private void performLogin(String username) {
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.manage().deleteAllCookies();
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

    private ScimUser createRandomUser() {
        String username = new RandomValueStringGenerator(5).generate().toLowerCase();
        ScimUser user = new ScimUser(null, username, "first", "last");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword(USER_PASSWORD);
        user.setVerified(true);
        return IntegrationTestUtils.createUser(adminAccessToken,
            baseUrl,
            user,
            mfaZone.getId()
        );
    }

}
