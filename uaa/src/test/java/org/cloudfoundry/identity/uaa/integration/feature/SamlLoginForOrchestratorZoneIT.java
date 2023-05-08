package org.cloudfoundry.identity.uaa.integration.feature;


import org.cloudfoundry.identity.uaa.integration.feature.orchestrator.uilocators.IdploginUI;
import org.cloudfoundry.identity.uaa.integration.feature.orchestrator.uilocators.SploginUI;
import org.cloudfoundry.identity.uaa.integration.feature.orchestrator.utils.IntegrationUtilsOrchestrator;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.NoSuchElementException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Arrays;
import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class SamlLoginForOrchestratorZoneIT extends SamlBaseIT {


    @Before
    public void clearWebDriverOfCookies() throws Exception {
        samlTestUtils.initialize();
        webDriver.get(baseUrl + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get(baseUrl.replace("localhost", "samlidpzone.localhost") + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get(baseUrl.replace("localhost", "samlspzone.localhost") + "/logout.do");
        webDriver.manage().deleteAllCookies();
        assertTrue("Expected samlidpzone.localhost and samlspzone.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
    }

    @Before
    public void setup() {
        String token = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");

        ScimGroup group = new ScimGroup(null, "zones.samlidpzone.admin", null);
        IntegrationTestUtils.createGroup(token, "", baseUrl, group);

        group = new ScimGroup(null, "zones.samlspzone.admin", null);
        IntegrationTestUtils.createGroup(token, "", baseUrl, group);

        group = new ScimGroup(null, "zones.uaa.admin", null);
        IntegrationTestUtils.createGroup(token, "", baseUrl, group);
    }

    protected boolean doesSupportZoneDNS() {
        try {
            return Arrays.equals(Inet4Address.getByName("samlidpzone.localhost").getAddress(),
                    new byte[]{127, 0, 0, 1})
                    && Arrays.equals(Inet4Address.getByName("samlspzone.localhost").getAddress(),
                    new byte[]{127, 0, 0, 1});
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * In this test samlidpzone acts as the SAML IdP and samlspzone acts as the SAML SP.
     */
    @Test
    public void testCrossZoneSamlIntegration() throws Throwable {
        String idpZoneId = "samlidpzone";
        String idpZoneUrl = baseUrl.replace("localhost", idpZoneId + ".localhost");
        String spZoneId = "samlspzone";
        String spZoneUrl = baseUrl.replace("localhost", spZoneId + ".localhost");
        RestTemplate orchestratorZoneProvisioner = getIdentityClient();
        //Creating Orch IDP Zone
        IdentityZone idpZone = IntegrationUtilsOrchestrator.createOrchZone(orchestratorZoneProvisioner, baseUrl, idpZoneId, idpZoneId);
        String idpZoneUserEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        //Create user for IDP Admin
        createZoneUser(idpZoneId, idpZoneUserEmail, idpZoneUrl);
        //Creating Orch SP Zone
        IdentityZone spZone = IntegrationUtilsOrchestrator.createOrchZone(orchestratorZoneProvisioner, baseUrl, spZoneId, spZoneId);
        //Get Client credentials for SP Admin token
        String spZoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        //Get IDP Metadata
        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createZone1IdpDefinition(IDP_ENTITY_ID);
        // Create IDP
        getSamlIdentityProvider(spZone.getId(), spZoneAdminToken, samlIdentityProviderDefinition);
        //Get SP Metadata
        SamlServiceProviderDefinition samlServiceProviderDefinition = createZone2SamlSpDefinition("cloudfoundry-saml-login");
        // Create SP
        getSamlServiceProvider(idpZone.getId(), spZoneAdminToken, samlServiceProviderDefinition, "samlspzone.cloudfoundry-saml-login", "Local SAML SP for samlspzone", baseUrl);
        //Login into SP with IDP credentials
        performLogin(idpZoneUserEmail,spZone, spZoneUrl);
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(spZoneUrl + "/logout.do");
    }

    public static SamlServiceProviderDefinition createZone2SamlSpDefinition(String alias) {
        return createLocalSamlSpDefinition(alias, "samlspzone");
    }

    public SamlIdentityProviderDefinition createZone1IdpDefinition(String alias) {
        return createLocalSamlIdpDefinition(alias, "samlidpzone");
    }

    private ScimUser createZoneUser(String idpZoneId, String zoneUserEmail, String zoneUrl) {
        RestTemplate zoneAdminClient = IntegrationTestUtils.getClientCredentialsTemplate(IntegrationTestUtils
                .getClientCredentialsResource(zoneUrl, new String[0], "admin", "adminsecret"));
        return IntegrationTestUtils.createUserWithPhone(zoneAdminClient, zoneUrl, zoneUserEmail, "Dana", "Scully", zoneUserEmail,
                true, "1234567890");
    }

    public void performLogin(String idpZoneUserEmail,IdentityZone spZone, String spZoneUrl) {
        IdploginUI ssoIdp = new IdploginUI(webDriver);
        SploginUI ssoSp = new SploginUI(webDriver);
        webDriver.get(spZoneUrl + "/");
        assertEquals(spZone.getName(), webDriver.getTitle());
        Cookie beforeLogin = webDriver.manage().getCookieNamed("JSESSIONID");
        assertNotNull(beforeLogin);
        assertNotNull(beforeLogin.getValue());
        ssoSp.clickOnSignInByGesso();
        try {

            ssoIdp.headLineCheck();

            ssoIdp.enterIDPuserName(idpZoneUserEmail);

            ssoIdp.enterIDPPassword("secr3T");

            ssoIdp.clickOnSignIn();
            assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));
            Cookie afterLogin = webDriver.manage().getCookieNamed("JSESSIONID");
            assertNotNull(afterLogin);
            assertNotNull(afterLogin.getValue());
            assertNotEquals(beforeLogin.getValue(), afterLogin.getValue());
        } catch (Exception e) {
            assertTrue("Http-Artifact binding is not supported", e instanceof NoSuchElementException);

        }
    }
}
