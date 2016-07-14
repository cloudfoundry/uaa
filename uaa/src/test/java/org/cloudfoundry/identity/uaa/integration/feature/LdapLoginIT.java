package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
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
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
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


    @Before
    public void clearWebDriverOfCookies() throws Exception {
        screenShootRule.setWebDriver(webDriver);
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl.replace("localhost", "testzone1.localhost") + "/logout.do");
        webDriver.get(baseUrl.replace("localhost", "testzone2.localhost") + "/logout.do");
        webDriver.manage().deleteAllCookies();
    }

    @Test
    public void ldapLogin_withValidSelfSignedCert() throws Exception {
        //ensure we are able to resolve DNS for hostname testzone2.localhost
        assumeTrue("Expected testzone1/2/3/4.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String zoneId = "testzone2";
        String zoneUrl = baseUrl.replace("localhost", "testzone2.localhost");

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
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), zoneId);

        //get the zone admin token
        String zoneAdminToken =
          IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
            UaaTestAccounts.standard(serverRunning),
            "identity",
            "identitysecret",
            email,
            "secr3T");

        LdapIdentityProviderDefinition ldapIdentityProviderDefinition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
          "ldaps://52.87.212.253:636/",
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

        IdentityProvider provider = new IdentityProvider();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.LDAP);
        provider.setActive(true);
        provider.setConfig(ldapIdentityProviderDefinition);
        provider.setOriginKey(OriginKeys.LDAP);
        provider.setName("simplesamlphp for uaa");
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);

        webDriver.get(zoneUrl + "/login");
        webDriver.findElement(By.name("username")).sendKeys("marissa4");
        webDriver.findElement(By.name("password")).sendKeys("ldap4");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to"));
    }

    @Test
    public void ldapLogin_withExpiredSelfSignedCert() throws Exception {
        //ensure we are able to resolve DNS for hostname testzone1.localhost
        assumeTrue("Expected testzone1/2/3/4.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String zoneId = "testzone1";
        String zoneUrl = baseUrl.replace("localhost", "testzone1.localhost");

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
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), zoneId);

        //get the zone admin token
        String zoneAdminToken =
                IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                        UaaTestAccounts.standard(serverRunning),
                        "identity",
                        "identitysecret",
                        email,
                        "secr3T");

        LdapIdentityProviderDefinition ldapIdentityProviderDefinition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                "ldaps://52.20.5.106:636/",
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

        IdentityProvider provider = new IdentityProvider();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.LDAP);
        provider.setActive(true);
        provider.setConfig(ldapIdentityProviderDefinition);
        provider.setOriginKey(OriginKeys.LDAP);
        provider.setName("simplesamlphp for uaa");
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);

        webDriver.get(zoneUrl + "/login");
        webDriver.findElement(By.name("username")).sendKeys("marissa4");
        webDriver.findElement(By.name("password")).sendKeys("ldap4");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Welcome to The Twiglet Zone[" + zoneId + "]!"));
    }
}
