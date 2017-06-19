package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFail;
import org.cloudfoundry.identity.uaa.login.test.LoginServerClassRunner;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_NONE;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_SIMPLE;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeTrue;

@RunWith(LoginServerClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class LdapLoginIT {

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    @Rule
    public ScreenshotOnFail screenShootRule = new ScreenshotOnFail();

    @Autowired
    RestOperations restOperations;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestClient testClient;

    ServerRunning serverRunning = ServerRunning.isRunning();
    private String zoneAdminToken;

    @Before
    public void clearWebDriverOfCookies() throws Exception {
        screenShootRule.setWebDriver(webDriver);
        for (String domain : Arrays.asList("localhost", "testzone1.localhost", "testzone2.localhost", "testzone3.localhost", "testzone4.localhost")) {
            webDriver.get(baseUrl.replace("localhost", domain) + "/logout.do");
            webDriver.manage().deleteAllCookies();
        }
    }
    @Test
    public void ldapLogin_with_StartTLS() throws Exception {
        Long beforeTest = System.currentTimeMillis();
        performLdapLogin("testzone2", "ldap://52.87.212.253:389/", true, true, "marissa4", "ldap4");
        Long afterTest = System.currentTimeMillis();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));
        ScimUser user = IntegrationTestUtils.getUserByZone(zoneAdminToken, baseUrl, "testzone2", "marissa4");
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
        IntegrationTestUtils.validateAccountChooserCookie(baseUrl.replace("localhost","testzone2.localhost"), webDriver);
    }

    @Test
    public void ldap_login_using_utf8_characters() throws Exception {
        performLdapLogin("testzone2", "ldap://52.87.212.253:389/", true, true, "\u7433\u8D3A", "koala");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));
    }

    private void performLdapLogin(String subdomain, String ldapUrl) throws Exception {
        performLdapLogin(subdomain, ldapUrl, false, false, "marissa4", "ldap4");
    }
    private void performLdapLogin(String subdomain, String ldapUrl, boolean startTls, boolean skipSSLVerification, String username, String password) throws Exception {
        //ensure we are able to resolve DNS for hostname testzone2.localhost
        assumeTrue("Expected testzone1/2/3/4.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        //ensure that certs have been added to truststore via gradle
        String zoneId = subdomain;
        String zoneUrl = baseUrl.replace("localhost", subdomain + ".localhost");

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
          IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        //admin client token - to create users
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
          IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        //create the zone
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId);

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() + "@ldaptesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), zoneId);

        //get the zone admin token
        zoneAdminToken =
          IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
            UaaTestAccounts.standard(serverRunning),
            "identity",
            "identitysecret",
            email,
            "secr3T");

        LdapIdentityProviderDefinition ldapIdentityProviderDefinition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
          ldapUrl,
          "cn=admin,dc=test,dc=com",
          "password",
          "dc=test,dc=com",
          "cn={0}",
          "ou=scopes,dc=test,dc=com",
          "member={0}",
          "mail",
          null,
          false,
          true,
          true,
          100,
          false);
        ldapIdentityProviderDefinition.setTlsConfiguration(startTls ? LDAP_TLS_SIMPLE : LDAP_TLS_NONE);
        ldapIdentityProviderDefinition.setSkipSSLVerification(skipSSLVerification);

        IdentityProvider provider = new IdentityProvider();
        provider.setIdentityZoneId(zoneId);
        provider.setType(LDAP);
        provider.setActive(true);
        provider.setConfig(ldapIdentityProviderDefinition);
        provider.setOriginKey(LDAP);
        provider.setName("simplesamlphp for uaa");
        IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);

        webDriver.get(zoneUrl + "/login");
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
    }
}
