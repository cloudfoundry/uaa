package org.cloudfoundry.identity.uaa.degraded;


import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFail;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.cloudfoundry.identity.uaa.authentication.AbstractClientParametersAuthenticationFilter.CLIENT_SECRET;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.springframework.test.context.TestExecutionListeners.MergeMode.MERGE_WITH_DEFAULTS;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
@TestExecutionListeners(value = { ScreenshotOnFail.class }, mergeMode = MERGE_WITH_DEFAULTS)
public class DegradedSamlLoginTests {

    private static final String SAML_USERNAME = "samluser1";
    private static final String SAML_PASSWORD = "SamlUser10@";
    private static final String ZONE_AUTHCODE_CLIENT_ID = "exampleClient";
    private static final String ZONE_AUTHCODE_CLIENT_SECRET = "secret";
    public static final String ZONE_ADMIN = "admin";
    @Value("${ZONE_ADMIN_SECRET:adminsecret}")
    String zoneAdminSecret;

    @Value("${PUBLISHED_HOST:predix-uaa-integration}")
    String publishedHost;

    @Value("${CF_DOMAIN:run.aws-usw02-dev.ice.predix.io}")
    String cfDomain;

    @Value("${BASIC_AUTH_CLIENT_ID:app}")
    String basicAuthClientId;

    @Value("${BASIC_AUTH_CLIENT_SECRET:appclientsecret}")
    String basicAuthClientSecret;

    @Autowired
    RestOperations restOperations;

    @Autowired
    public Environment environment;

    @Autowired
    WebDriver webDriver;

    protected final static Logger logger = LoggerFactory.getLogger(DegradedSamlLoginTests.class);
    private final static String zoneSubdomain = "test-app-zone";
    private String protocol;
    private String baseUrl;
    private String testRedirectUri;
    private String zoneAdminToken;
    private String baseUaaZoneHost;

    @Before
    public void setup() throws Exception {
        baseUaaZoneHost = Boolean.valueOf(environment.getProperty("RUN_AGAINST_CLOUD")) ? (publishedHost + "." + cfDomain) : "localhost:8080/uaa";
        protocol = Boolean.valueOf(environment.getProperty("RUN_AGAINST_CLOUD")) ? "https://" : "http://";
        baseUrl = protocol + zoneSubdomain + "." + baseUaaZoneHost;
        testRedirectUri = protocol +  "www.example.com";
        zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, ZONE_ADMIN, zoneAdminSecret);
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
        } catch(HttpServerErrorException e) {
            assertThat(e.getMessage(), Matchers.containsString("503"));
        }
    }

    @Test
    public void testGetTokenKey() throws Exception {
        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        HttpEntity getHeaders = new HttpEntity(headers);
        ResponseEntity<Map> tokenKeyGet = restTemplate.exchange(
                baseUrl + "/token_key",
                HttpMethod.GET,
                getHeaders,
                Map.class
        );
        assertEquals(HttpStatus.OK, tokenKeyGet.getStatusCode());
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
        } catch(HttpServerErrorException e) {
            assertThat(e.getMessage(), Matchers.containsString("503"));
        }
    }

    @Test
    public void testPasswordTokenAndCheckToken() throws Exception {
        MultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("username", "marissa");
        postBody.add("password", "KOala12@");
        postBody.add(GRANT_TYPE, "password");
        postBody.add(RESPONSE_TYPE, "token");
        postBody.add("token_format", "opaque");

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(HttpHeaders.ACCEPT, APPLICATION_JSON_VALUE);
        headers.add(HttpHeaders.CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE);
        headers.set("Authorization", getAuthorizationHeader(basicAuthClientId, basicAuthClientSecret));

        ResponseEntity<Map> tokenResponse = new RestTemplate().exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<MultiValueMap>(postBody, headers), Map.class);
        assertThat(tokenResponse.getStatusCode().value(), Matchers.equalTo(200));

        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", accessToken.getValue());

        ResponseEntity<Map> checkTokenResponse = new RestTemplate().exchange(baseUrl + "/check_token", HttpMethod.POST, new HttpEntity<>(formData, headers), Map.class);
        assertEquals(checkTokenResponse.getStatusCode(), HttpStatus.OK);
        logger.info("check token response: " + checkTokenResponse.getBody());
        assertEquals("marissa", checkTokenResponse.getBody().get("user_name"));
    }

    @Test
    public void testImplicitTokenAndCheckToken() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/oauth/authorize?client_id=cf&response_type=token&redirect_uri=" + testRedirectUri +"/cf");
        logger.info("testImplicitTokenAndCheckToken() webdriver page source" + webDriver.getPageSource());
        webDriver.manage().timeouts().pageLoadTimeout(20, TimeUnit.SECONDS);
        assertThat(webDriver.getCurrentUrl(), Matchers.containsString("login"));
        logger.info(webDriver.getCurrentUrl());
        webDriver.findElement(By.xpath("//title[contains(text(), '" + zoneSubdomain + "')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys("marissa");
        webDriver.findElement(By.name("password")).sendKeys("KOala12@");
        webDriver.findElement(By.xpath("//input[@type='submit']")).click();

        //Ensure the browser/webdriver processes all the flows
        webDriver.manage().timeouts().implicitlyWait(20, TimeUnit.SECONDS);
        //Get the http archive logs
        String requestUrl = webDriver.getCurrentUrl();
        logger.info("request url: " + requestUrl);
        assertThat(requestUrl, Matchers.startsWith(testRedirectUri + "/cf#token_type=bearer&access_token="));
        String tokenprefixedString = requestUrl.split("access_token=")[1];
        String accessToken = tokenprefixedString.split("&")[0];

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", accessToken);

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(HttpHeaders.ACCEPT, APPLICATION_JSON_VALUE);
        headers.add(HttpHeaders.CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE);
        headers.set("Authorization", getAuthorizationHeader(basicAuthClientId, basicAuthClientSecret));

        ResponseEntity<Map> checkTokenResponse = new RestTemplate().exchange(baseUrl + "/check_token", HttpMethod.POST, new HttpEntity<>(formData, headers), Map.class);
        assertEquals(checkTokenResponse.getStatusCode(), HttpStatus.OK);
        logger.info("check token response: " + checkTokenResponse.getBody());
        assertEquals("marissa", checkTokenResponse.getBody().get("user_name"));
    }

    @Test
    public void testOidcSamlAuthcodeTokenAndCheckToken() throws Exception {
        testOidcSamlAuthcodeTokenAndCheckToken("/oauth/authorize?client_id=" + ZONE_AUTHCODE_CLIENT_ID + "&response_type=code&redirect_uri=" + testRedirectUri);
    }

    private void testOidcSamlAuthcodeTokenAndCheckToken(String firstUrl) throws Exception {
        Assert.assertTrue("Expected app zone subdomain to exist", findZoneInUaa());


        webDriver.get(baseUrl + firstUrl);
        //idp_discovery in test-platform-zone
        assertThat(webDriver.getCurrentUrl(), Matchers.containsString("test-platform-zone"));
        webDriver.findElement(By.name("email")).clear();
        webDriver.findElement(By.name("email")).sendKeys(SAML_USERNAME + "@ge.com");
        webDriver.findElement(By.cssSelector(".form-group input[value='Next']")).click();
        logger.info(webDriver.getCurrentUrl());
        webDriver.findElement(By.xpath("//h1[contains(text(), 'test-saml-zone')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(SAML_USERNAME);
        webDriver.findElement(By.name("password")).sendKeys(SAML_PASSWORD);
        webDriver.findElement(By.xpath("//input[@type='submit']")).click();

        //Ensure the browser/webdriver processes all the flows
        webDriver.manage().timeouts().implicitlyWait(20, TimeUnit.SECONDS);

        String lastRequestUrl = webDriver.getCurrentUrl();
        logger.info("last request url: " + lastRequestUrl);
        assertThat(lastRequestUrl, Matchers.containsString(testRedirectUri));
        String authcode = lastRequestUrl.split("code=")[1];
        logger.info("AuthCode is: ",authcode);

        MultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add(CLIENT_ID, ZONE_AUTHCODE_CLIENT_ID);
        postBody.add(CLIENT_SECRET, ZONE_AUTHCODE_CLIENT_SECRET);
        postBody.add("code", authcode);
        postBody.add(GRANT_TYPE, "authorization_code");
        postBody.add(REDIRECT_URI, testRedirectUri);
        postBody.add(RESPONSE_TYPE, "token");

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(HttpHeaders.ACCEPT, APPLICATION_JSON_VALUE);
        headers.add(HttpHeaders.CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE);

        ResponseEntity<Map> tokenResponse = new RestTemplate().exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<MultiValueMap>(postBody, headers), Map.class);
        assertThat(tokenResponse.getStatusCode().value(), Matchers.equalTo(200));

        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", accessToken.getValue());

        headers.set("Authorization", getAuthorizationHeader(ZONE_ADMIN, zoneAdminSecret));

        ResponseEntity<Map> checkTokenResponse = new RestTemplate().exchange(baseUrl + "/check_token", HttpMethod.POST, new HttpEntity<>(formData, headers), Map.class);
        assertEquals(checkTokenResponse.getStatusCode(), HttpStatus.OK);
        logger.info("check token response: " + checkTokenResponse.getBody());
        assertEquals(SAML_USERNAME, checkTokenResponse.getBody().get("user_name"));

    }

    private String getAuthorizationHeader(String username, String password) {
        String credentials = String.format("%s:%s", username, password);
        return String.format("Basic %s", new String(Base64.encode(credentials.getBytes())));
    }


    private boolean findZoneInUaa() {
        RestTemplate zoneAdminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], ZONE_ADMIN, zoneAdminSecret));
        ResponseEntity<String> responseEntity = zoneAdminClient.getForEntity(baseUrl + "/login", String.class);

        logger.info("response body: " + responseEntity.getStatusCode());
        return responseEntity.getStatusCode() == HttpStatus.OK;
    }
}