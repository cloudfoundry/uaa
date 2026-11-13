package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.integration.pageObjects.Page;
import org.cloudfoundry.identity.uaa.integration.pageObjects.SamlErrorPage;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFailExtension;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;

/**
 * A failed SAML sign-in during an authorization request: the browser is only sent back to the
 * redirect_uri of the request when the client has registered it.
 */
@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
@ExtendWith(ScreenshotOnFailExtension.class)
class SamlFailureRedirectIT {

    private static final String SAML_ENDPOINT = "/saml/SSO/alias/cloudfoundry-saml-login";

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    UaaWebDriver webDriver;

    @Autowired
    TestClient testClient;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @BeforeEach
    void logout() {
        webDriver.get("%s/logout.do".formatted(baseUrl));
        webDriver.manage().deleteAllCookies();
    }

    @Test
    void failedSamlSignInShowsTheErrorPageForAnUnregisteredRedirectUri() {
        String clientId = createClient();

        startAuthorization(clientId, "http://unregistered.example.com/page");
        postUnusableSamlResponse();

        new SamlErrorPage(webDriver);
        assertThat(webDriver.getCurrentUrl()).doesNotContain("unregistered.example.com");
    }

    @Test
    void failedSamlSignInRedirectsToARegisteredRedirectUriWithTheError() {
        String clientId = createClient();

        startAuthorization(clientId, baseUrl + "/login");
        postUnusableSamlResponse();

        Page.assertThatUrlEventuallySatisfies(webDriver, url -> url
                .startsWith(baseUrl + "/login?error=access_denied&error_description="));
    }

    private String createClient() {
        String adminToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials",
                "clients.read clients.write clients.secret clients.admin");
        String clientId = "saml-failure-" + UUID.randomUUID();
        UaaClientDetails client = new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none",
                baseUrl + "/login");
        client.setClientSecret("secret");
        testClient.createClient(adminToken, client);
        return clientId;
    }

    private void startAuthorization(String clientId, String redirectUri) {
        webDriver.get("%s/oauth/authorize?client_id=%s&response_type=code&redirect_uri=%s"
                .formatted(baseUrl, clientId, URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)));
    }

    /**
     * Posts a SAMLResponse that cannot be processed, like an identity provider response that is rejected.
     */
    private void postUnusableSamlResponse() {
        webDriver.getJavascriptExecutor().executeScript(
                "var form = document.createElement('form');"
                        + "form.method = 'POST';"
                        + "form.action = arguments[0];"
                        + "var field = document.createElement('input');"
                        + "field.type = 'hidden';"
                        + "field.name = 'SAMLResponse';"
                        + "field.value = 'bm90IGEgc2FtbCByZXNwb25zZQ==';"
                        + "form.appendChild(field);"
                        + "document.body.appendChild(form);"
                        + "form.submit();",
                baseUrl + SAML_ENDPOINT);
    }
}
