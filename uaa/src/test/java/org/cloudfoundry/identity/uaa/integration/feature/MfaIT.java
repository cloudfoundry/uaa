package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.mfa_provider.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.StringUtils;

import static org.junit.Assert.assertTrue;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class MfaIT {

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    TestClient testClient;

    ServerRunning serverRunning = ServerRunning.isRunning();

    @Test
    public void createMfaProvider() throws Exception {
        MfaProvider<GoogleMfaProviderConfig> provider = new MfaProvider();
        provider.setConfig(new GoogleMfaProviderConfig());
        provider.setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        provider.setName("testMfaProvider");

        String adminToken = IntegrationTestUtils.getZoneAdminToken(baseUrl, serverRunning);
        MfaProvider result = IntegrationTestUtils.createGoogleMfaProvider(baseUrl, adminToken, provider, "");
        assertTrue("id is not empty", StringUtils.hasText(result.getId()));
    }

}
