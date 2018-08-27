package org.cloudfoundry.identity.uaa.integration;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.feature.TestClient;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.mfa.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import static org.junit.Assert.assertTrue;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class MfaProviderEndpointsIntegrationTests {

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    TestClient testClient;

    ServerRunning serverRunning = ServerRunning.isRunning();
    private String adminToken;
    private MfaProvider<GoogleMfaProviderConfig> mfaProvider;

    @Before
    public void setup() throws Exception {
        adminToken = IntegrationTestUtils.getZoneAdminToken(baseUrl, serverRunning);

        mfaProvider = new MfaProvider();
        mfaProvider.setConfig(new GoogleMfaProviderConfig());
        mfaProvider.setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        mfaProvider.setName("testMfaProvider");
    }

    @Test
    public void createMfaProvider() {
        MfaProvider result = IntegrationTestUtils.createGoogleMfaProvider(baseUrl, adminToken, mfaProvider, "");
        assertTrue("id is not empty", StringUtils.hasText(result.getId()));
    }

    @Test
    public void createMfaProviderInZone() throws Exception {
        ClientCredentialsResourceDetails adminResource = IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret");
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                adminResource);

        IdentityZone mfaZone = IntegrationTestUtils.createZoneOrUpdateSubdomain(adminClient, baseUrl, "testzone1", "testzone1", null);
        String zoneUrl = baseUrl.replace("localhost", mfaZone.getSubdomain() + ".localhost");

        String zoneAdminToken = IntegrationTestUtils.getZoneAdminToken(baseUrl, serverRunning, mfaZone.getId());
        BaseClientDetails zoneClient = new BaseClientDetails("mfaAdmin", null, "", "client_credentials", "uaa.admin");
        zoneClient.setClientSecret("secret");
        IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, mfaZone.getId(), zoneClient);

        String inZoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(zoneUrl, "mfaAdmin", "secret");

        MfaProvider result = IntegrationTestUtils.createGoogleMfaProvider(zoneUrl, inZoneAdminToken, mfaProvider, "");
        assertTrue("id is not empty", StringUtils.hasText(result.getId()));


    }

}
