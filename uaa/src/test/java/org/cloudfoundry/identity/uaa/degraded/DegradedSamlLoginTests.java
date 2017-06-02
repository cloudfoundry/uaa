package org.cloudfoundry.identity.uaa.degraded;


import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFail;
import org.cloudfoundry.identity.uaa.login.test.LoginServerClassRunner;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.logging.LogEntry;
import org.openqa.selenium.support.ui.ExpectedCondition;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.authentication.AbstractClientParametersAuthenticationFilter.CLIENT_SECRET;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.junit.Assert.*;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;

@RunWith(LoginServerClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class DegradedSamlLoginTests {

    @Rule
    public ScreenshotOnFail screenShootRule = new ScreenshotOnFail();

    @Autowired
    RestOperations restOperations;

    @Autowired
    WebDriver webDriver;

    protected final static Logger logger = LoggerFactory.getLogger(DegradedSamlLoginTests.class);
    private final static String zoneSubdomain = "test-app-zone";
    private String baseUrl;
    private String zoneAdminToken;
    private String samlUsername = "samluser1";
    private String samlPassword = "samluser1";
    private String zoneAuthcodeClientId = "exampleClient";
    private String zoneAuthcodeClientSecret = "secret";

    @Before
    public void setup() throws Exception {
        baseUrl = "http://" + zoneSubdomain + ".localhost:8080/uaa";
        zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");

        screenShootRule.setWebDriver(webDriver);
    }

    @Test
    public void testScimResourcesReadOnly() throws Exception {
        ScimGroup group = IntegrationTestUtils.getGroup(zoneAdminToken, null, baseUrl, "uaa.admin");
        assertEquals("uaa.admin", group.getDisplayName());

        //Test Degraded mode prevents Write operation
        ScimGroup scimGroup = new ScimGroup(null, "example.group", "test-app-zone");
        try {
            IntegrationTestUtils.createGroup(zoneAdminToken, null, baseUrl, scimGroup);
            Assert.fail("Failure: Group creation should not be allowed");
        } catch(AssertionError e) {
            assertThat(e.getMessage(), Matchers.containsString("403"));
        }
    }


    @Test
    public void testIdpsReadOnly() throws Exception {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        HttpEntity getHeaders = new HttpEntity(headers);
        ResponseEntity<String> providerGet = client.exchange(
                baseUrl + "/identity-providers",
                HttpMethod.GET,
                getHeaders,
                String.class
        );
        assertEquals(HttpStatus.OK, providerGet.getStatusCode());

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = IntegrationTestUtils.createSimplePHPSamlIDP("simplesamlphp", "test-app-zone");
        samlIdentityProviderDefinition.setAddShadowUserOnLogin(true);
        IdentityProvider provider = new IdentityProvider();
        provider.setIdentityZoneId(OriginKeys.UAA);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("exampleIdp");

        try {
            headers = new LinkedMultiValueMap<>();
            headers.add("Accept", APPLICATION_JSON_VALUE);
            headers.add("Authorization", "bearer "+ zoneAdminToken);
            headers.add("Content-Type", APPLICATION_JSON_VALUE);
            HttpEntity httpEntity = new HttpEntity(provider, headers);
            ResponseEntity<String> providerPost = client.exchange(
                    baseUrl + "/identity-providers",
                    HttpMethod.POST,
                    httpEntity,
                    String.class
            );
            Assert.fail("Failure: Idp creation should not be allowed");
        } catch(HttpClientErrorException e) {
            assertThat(e.getMessage(), Matchers.containsString("403"));
        }
    }

    @Test
    public void testOidcSamlAuthcodeTokenAndCheckToken() throws Exception {
        testOidcSamlAuthcodeTokenAndCheckToken("/oauth/authorize?client_id=" + zoneAuthcodeClientId + "&response_type=code");
    }

    private void testOidcSamlAuthcodeTokenAndCheckToken(String firstUrl) throws Exception {
        Assert.assertTrue("Expected app zone subdomain to exist", findZoneInUaa());


        webDriver.get(baseUrl + firstUrl);
        //idp_discovery in test-platform-zone
        assertThat(webDriver.getCurrentUrl(), Matchers.containsString("test-platform-zone"));
        webDriver.findElement(By.name("email")).clear();
        webDriver.findElement(By.name("email")).sendKeys(samlUsername + "@ge.com");
        webDriver.findElement(By.name("commit")).click();
        logger.info(webDriver.getCurrentUrl());
        webDriver.findElement(By.xpath("//h1[contains(text(), 'test-saml-zone')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(samlUsername);
        webDriver.findElement(By.name("password")).sendKeys(samlPassword);
        webDriver.findElement(By.xpath("//input[@type='submit']")).click();

        Thread.sleep(1000);
        List<LogEntry> harLogEntries = webDriver.manage().logs().get("har").getAll();
        LogEntry lastLogEntry = harLogEntries.get(harLogEntries.size() - 1);

        String lastRequestUrl = getRequestUrlFromHarLogEntry(lastLogEntry);
        logger.info("last request url: " + lastRequestUrl);
        assertThat(lastRequestUrl, Matchers.containsString("localhost:5000"));
        String authcode = lastRequestUrl.split("code=")[1];
        logger.info("AuthCode is: ",authcode);

        MultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add(CLIENT_ID, zoneAuthcodeClientId);
        postBody.add(CLIENT_SECRET, zoneAuthcodeClientSecret);
        postBody.add("code", authcode);
        postBody.add(GRANT_TYPE, "authorization_code");
        postBody.add(RESPONSE_TYPE, "token");

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(HttpHeaders.ACCEPT, APPLICATION_JSON_VALUE);
        headers.add(HttpHeaders.CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE);

        ResponseEntity<Map> tokenResponse = new RestTemplate().exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<MultiValueMap>(postBody, headers), Map.class);
        assertThat(tokenResponse.getStatusCode().value(), Matchers.equalTo(200));

        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());
        Map<String, String> body = tokenResponse.getBody();

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", accessToken.getValue());

        headers.set("Authorization", getAuthorizationHeader("admin", "adminsecret"));

        ResponseEntity<Map> checkTokenResponse = new RestTemplate().exchange(baseUrl + "/check_token", HttpMethod.POST, new HttpEntity<>(formData, headers), Map.class);
        assertEquals(checkTokenResponse.getStatusCode(), HttpStatus.OK);
        logger.info("check token response: " + checkTokenResponse.getBody());
        assertEquals(samlUsername, checkTokenResponse.getBody().get("user_name"));

    }

    private String getAuthorizationHeader(String username, String password) {
        String credentials = String.format("%s:%s", username, password);
        return String.format("Basic %s", new String(Base64.encode(credentials.getBytes())));
    }


    private String getRequestUrlFromHarLogEntry(LogEntry logEntry)
            throws IOException {

        Map<String, Object> message = JsonUtils.readValue(logEntry.getMessage(), new TypeReference<Map<String,Object>>() {});
        Map<String, Object> log = (Map<String, Object>) message.get("log");
        List<Object> entries = (List<Object>) log.get("entries");
        Map<String, Object> lastEntry = (Map<String, Object>) entries.get(entries.size() - 1);
        Map<String, Object> request = (Map<String, Object>) lastEntry.get("request");
        String url = (String) request.get("url");
        return url;
    }

    private boolean findZoneInUaa() {
        RestTemplate zoneAdminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret"));
        ResponseEntity<String> responseEntity = zoneAdminClient.getForEntity(baseUrl + "/login", String.class);

        logger.info("response body: " + responseEntity.getStatusCode());
        return responseEntity.getStatusCode() == HttpStatus.OK;
    }



}
