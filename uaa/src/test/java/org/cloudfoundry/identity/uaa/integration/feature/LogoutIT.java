package org.cloudfoundry.identity.uaa.integration.feature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.Inet4Address;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.util.Arrays;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.login.test.LoginServerClassRunner;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestTemplate;

@RunWith(LoginServerClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class LogoutIT {
	
	@Autowired 
	@Rule
    public IntegrationTestRule integrationTestRule;
	
    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;
    
    ServerRunning serverRunning = ServerRunning.isRunning();  
    
    @Before
    @After
    public void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        }catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
        
        try {
	        webDriver.get(baseUrl.replace("localhost", "testzone1.localhost") + "/logout.do");
        }catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
	        webDriver.get(baseUrl.replace("localhost", "testzone1.localhost") + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }
    
    protected boolean doesSupportZoneDNS() {
        try {
            return Arrays.equals(Inet4Address.getByName("testzone1.localhost").getAddress(), new byte[] {127,0,0,1});
        } catch (UnknownHostException e) {
            return false;
        }
    }
    
    private IdentityZone fixtureIdentityZone(String id, String subdomain) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(subdomain);
        identityZone.setName("The Twiglet Zone[" + id + "]");
        identityZone.setDescription("Like the Twilight Zone but tastier[" + id + "].");
        identityZone.getConfig().getLinks().getLogout().setWhitelist(Arrays.asList(new String[] {baseUrl + "/login"}));
        return identityZone;
    }
    
    private IdentityZone createZoneSubdomain(RestTemplate client,
            String url,
            String id,
            String subdomain) {
        ResponseEntity<String> zoneGet = client.getForEntity(url + "/identity-zones/{id}", String.class, id);
        if (zoneGet.getStatusCode()==HttpStatus.OK) {
	        client.delete(url + "/identity-zones/{id}",id);
        }
        IdentityZone identityZone = fixtureIdentityZone(id, subdomain);
        ResponseEntity<IdentityZone> zone = client.postForEntity(url + "/identity-zones", identityZone, IdentityZone.class);
        return zone.getBody();
    }
    
    @Test
    public void testLogoutWithRedirect() throws Exception {
        assertTrue("Expected testzone1.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String zoneId = "testzone1";
        String zoneUrl = baseUrl.replace("localhost",zoneId+".localhost");

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        //create the zone
        createZoneSubdomain(identityClient, baseUrl, zoneId, zoneId);

        String redirectUrl = baseUrl + "/login";
        webDriver.get(zoneUrl + "/logout.do?redirect=" + URLEncoder.encode(redirectUrl, "UTF-8"));
        assertEquals(redirectUrl, webDriver.getCurrentUrl());
    }
}
