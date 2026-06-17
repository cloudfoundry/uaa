package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.pageObjects.LoginPage;
import org.cloudfoundry.identity.uaa.integration.pageObjects.OAuthErrorPage;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFailExtension;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.WebElement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test demonstrating the concurrent multi-tab external login scenario.
 *
 * <h2>Scenario</h2>
 * <ol>
 *   <li>Tab 1 loads the UAA login page — UAA generates {@code state=STATE_1} and embeds it in
 *       the IDP link href; the session stores {@code STATE_1}.</li>
 *   <li>Tab 2 loads the UAA login page — UAA generates {@code state=STATE_2}, which
 *       <em>overwrites</em> {@code STATE_1} in the session; the link href now carries {@code STATE_2}.</li>
 *   <li>Tab 1 returns from the IDP with {@code STATE_1}. The session holds {@code STATE_2}
 *       — mismatch — UAA detects the concurrent login attempt and shows a friendly error page
 *       with a "Start a new login" link instead of a cryptic security error.</li>
 * </ol>
 *
 * <p>To run: {@code ./gradlew :cloudfoundry-identity-uaa:integrationTest --tests "*ConcurrentExternalLoginIT*"}
 * (requires a running UAA, e.g. started via {@code ./gradlew run})
 */
@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
@ExtendWith(ScreenshotOnFailExtension.class)
class ConcurrentExternalLoginIT {

    private static final String IDP_ORIGIN = "concurrent-login-test-idp";
    private static final String IDP_LINK_TEXT = "Concurrent Login Test IDP";

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    UaaWebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    private IdentityProvider<OIDCIdentityProviderDefinition> testIdp;
    private String adminToken;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        testIdp = registerTestOidcIdp();
        logout();
    }

    @AfterEach
    void tearDown() {
        if (testIdp != null) {
            IntegrationTestUtils.deleteProvider(adminToken, baseUrl, OriginKeys.UAA, IDP_ORIGIN);
        }
        logout();
    }

    /**
     * Verifies that the concurrent login error page is shown with a friendly message and a
     * link to restart the login flow.
     *
     * <p>A screenshot of the error page is saved to
     * {@code ~/build/cloudfoundry/uaa/screenshots/concurrent-login-error-page.png}
     * for attachment to the PR.
     */
    @Test
    void concurrentLogin_showsFriendlyErrorPage() throws Exception {
        // Step 1 — Load the login page once.
        //           UAA renders the IDP link with state=STATE_1 in the href and stores STATE_1 in the session.
        webDriver.get(baseUrl + "/login");
        WebElement idpLink = webDriver.findElement(By.linkText(IDP_LINK_TEXT));
        String idpHref = idpLink.getAttribute("href");
        String state1 = extractStateFromUrl(idpHref);
        assertThat(state1).as("state param must be present in the IDP link href").isNotBlank();

        // Step 2 — Load the login page AGAIN (simulating a second browser tab).
        //           UAA generates STATE_2 and overwrites STATE_1 in the session.
        webDriver.get(baseUrl + "/login");

        // Step 3 — Simulate Tab 1 returning from the IDP with the now-stale STATE_1.
        //           The session holds STATE_2 → UAA detects concurrent login.
        webDriver.get(baseUrl + "/login/callback/" + IDP_ORIGIN + "?code=fake-code&state=" + state1);

        // Step 4 — Verify the friendly error page.
        OAuthErrorPage errorPage = new OAuthErrorPage(webDriver);
        errorPage.assertConcurrentLoginMessageShown();
        errorPage.assertRestartLoginLinkPresent();

        // Step 5 — Save a screenshot for the PR.
        saveScreenshot("concurrent-login-error-page");
    }

    /**
     * Verifies that clicking "Start a new login" on the error page returns the user to the
     * normal login page.
     */
    @Test
    void concurrentLogin_startNewLoginLink_navigatesToLoginPage() throws Exception {
        webDriver.get(baseUrl + "/login");
        String state1 = extractStateFromUrl(webDriver.findElement(By.linkText(IDP_LINK_TEXT)).getAttribute("href"));
        webDriver.get(baseUrl + "/login");
        webDriver.get(baseUrl + "/login/callback/" + IDP_ORIGIN + "?code=fake-code&state=" + state1);

        OAuthErrorPage errorPage = new OAuthErrorPage(webDriver);
        LoginPage loginPage = errorPage.clickStartNewLogin(baseUrl);
        loginPage.assertThatLoginPageShown();
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────────

    private IdentityProvider<OIDCIdentityProviderDefinition> registerTestOidcIdp() throws Exception {
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        // Point at the local UAA as the "external" IDP — the test never completes the actual
        // auth flow, so the IDP endpoints only need to pass config validation.
        config.setAuthUrl(new URL(baseUrl + "/oauth/authorize"));
        config.setTokenUrl(new URL(baseUrl + "/oauth/token"));
        config.setTokenKeyUrl(new URL(baseUrl + "/token_key"));
        config.setIssuer(baseUrl + "/oauth/token");
        config.setUserInfoUrl(new URL(baseUrl + "/userinfo"));
        config.setShowLinkText(true);
        config.setLinkText(IDP_LINK_TEXT);
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        config.setScopes(List.of("openid"));

        IdentityProvider<OIDCIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setName(IDP_LINK_TEXT);
        provider.setOriginKey(IDP_ORIGIN);
        provider.setIdentityZoneId(OriginKeys.UAA);
        provider.setActive(true);
        provider.setConfig(config);

        return IntegrationTestUtils.createOrUpdateProvider(adminToken, baseUrl, provider);
    }

    /**
     * Parses the {@code state} query-parameter value from a URL string.
     */
    private static String extractStateFromUrl(String url) {
        try {
            String query = new URI(url).getQuery();
            if (query == null) {
                return null;
            }
            for (String param : query.split("&")) {
                if (param.startsWith("state=")) {
                    return param.substring("state=".length());
                }
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse state from URL: " + url, e);
        }
        return null;
    }

    /**
     * Saves a screenshot of the current browser state to
     * {@code ~/build/cloudfoundry/uaa/screenshots/<name>.png}.
     */
    private void saveScreenshot(String name) throws IOException {
        File screenshot = webDriver.getTakesScreenShot().getScreenshotAs(OutputType.FILE);
        Path dest = Paths.get(System.getProperty("user.home"), "build", "cloudfoundry", "uaa",
                "screenshots", name + ".png");
        Files.createDirectories(dest.getParent());
        Files.copy(screenshot.toPath(), dest, StandardCopyOption.REPLACE_EXISTING);
        System.out.printf("[ConcurrentExternalLoginIT] Screenshot saved → %s%n", dest.toAbsolutePath());
    }

    private void logout() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException _) {
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }
}
