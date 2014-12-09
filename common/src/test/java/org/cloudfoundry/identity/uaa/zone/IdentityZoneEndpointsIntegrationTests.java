package org.cloudfoundry.identity.uaa.zone;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.web.client.RestTemplate;

@OAuth2ContextConfiguration(IdentityZoneEndpointsIntegrationTests.IdentityClient.class)
public class IdentityZoneEndpointsIntegrationTests {
    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);
    
    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    private RestTemplate client;

    @Before
    public void createRestTemplate() throws Exception {
        client = (OAuth2RestTemplate) serverRunning.getRestTemplate();
        client.setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) throws IOException {
            }
        });
    }

    @Test
    public void testCreateZone() {
        String id = UUID.randomUUID().toString();
        String requestBody = "{\"identity_zone\":{\"id\":\""+id+"\", \"subdomain\":\""+id+"\", \"name\":\"testCreateZone() "+id+"\"}}";

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);

        ResponseEntity<Void> response = client.exchange(
                serverRunning.getUrl("/identity-zones/{id}"), 
                HttpMethod.PUT,
                new HttpEntity<>(requestBody, headers),
                new ParameterizedTypeReference<Void>() {}, 
                id);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
    }
    
    @Test
    public void testCreateZoneWithClient() throws IOException {
        IdentityZone idZone = new IdentityZone();
        String id = UUID.randomUUID().toString();
        idZone.setId(id);
        idZone.setSubdomain(id);
        idZone.setName("testCreateZone() "+id);
        IdentityZoneCreationRequest request = new IdentityZoneCreationRequest();
        request.setIdentityZone(idZone);
    	BaseClientDetails clientDetails = new BaseClientDetails("test123", null,null, "client_credentials", "clients.admin,scim.read,scim.write");
    	clientDetails.setClientSecret("testSecret");
    	request.setClientDetails(Collections.singletonList(clientDetails));
        ResponseEntity<Void> response = client.exchange(
                serverRunning.getUrl("/identity-zones/{id}"), 
                HttpMethod.PUT,
                new HttpEntity<IdentityZoneCreationRequest>(request), 
                new ParameterizedTypeReference<Void>() {}, 
                id);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        
		ResponseEntity<String> tokenResponse = getClientCredentialsToken(idZone.getSubdomain(), clientDetails.getClientId(), clientDetails.getClientSecret());
		assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
    }
    
    @Test
    public void testCreateZoneWithMultipleClients() throws IOException {
        IdentityZone idZone = new IdentityZone();
        String id = UUID.randomUUID().toString();
        idZone.setId(id);
        idZone.setSubdomain(id);
        idZone.setName("testCreateZone() "+id);
        IdentityZoneCreationRequest request = new IdentityZoneCreationRequest();
        request.setIdentityZone(idZone);
        List<BaseClientDetails> clientDetails = new ArrayList<BaseClientDetails>();
    	BaseClientDetails client1 = new BaseClientDetails("client1", null,null, "client_credentials", "clients.admin,scim.read,scim.write");
    	client1.setClientSecret("client1Secret");
    	clientDetails.add(client1);
    	BaseClientDetails client2 = new BaseClientDetails("client2", null,null, "client_credentials", "clients.admin,scim.read,scim.write");
    	client2.setClientSecret("client2Secret");
    	clientDetails.add(client2);
    	request.setClientDetails(clientDetails);
        ResponseEntity<Void> response = client.exchange(
                serverRunning.getUrl("/identity-zones/{id}"), 
                HttpMethod.PUT,
                new HttpEntity<IdentityZoneCreationRequest>(request), 
                new ParameterizedTypeReference<Void>() {}, 
                id);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        
		ResponseEntity<String> tokenResponse = getClientCredentialsToken(idZone.getSubdomain(), client1.getClientId(), client1.getClientSecret());
		assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
		tokenResponse = getClientCredentialsToken(idZone.getSubdomain(), client2.getClientId(), client2.getClientSecret());
		assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
    }
    
    private ResponseEntity<String> getClientCredentialsToken(String subdomain, String clientId, String clientSecret) throws IOException {
    	final String plainCreds = clientId+":"+clientSecret;
    	final byte[] plainCredsBytes = plainCreds.getBytes();
    	final byte[] base64CredsBytes = Base64.encodeBase64(plainCredsBytes);
    	final String base64Creds = new String(base64CredsBytes);
    	HttpHeaders headers = new HttpHeaders();
    	headers.add("Authorization", "Basic "+base64Creds);
    	headers.add("Host", subdomain+"."+serverRunning.getHostName());
		return serverRunning.getForString("oauth/token?grant_type=client_credentials", headers);
	}

	@Test
    public void testCreateZoneWithNonUniqueSubdomain() {
		IdentityZone idZone1 = new IdentityZone();
        String id1 = UUID.randomUUID().toString();
        idZone1.setId(id1);
        idZone1.setSubdomain(id1+"non-unique");
        idZone1.setName("testCreateZone() "+id1);
        IdentityZoneCreationRequest request1 = new IdentityZoneCreationRequest();
        request1.setIdentityZone(idZone1);
        ResponseEntity<Void> response1 = client.exchange(
                serverRunning.getUrl("/identity-zones/{id}"), 
                HttpMethod.PUT,
                new HttpEntity<IdentityZoneCreationRequest>(request1), 
                new ParameterizedTypeReference<Void>() {}, 
                id1);
        assertEquals(HttpStatus.CREATED, response1.getStatusCode());
        
        IdentityZone idZone2 = new IdentityZone();
        String id2 = UUID.randomUUID().toString();
        idZone2.setId(id2);
        idZone2.setSubdomain(id1+"non-unique");
        idZone2.setName("testCreateZone() "+id2);
        IdentityZoneCreationRequest request2 = new IdentityZoneCreationRequest();
        request2.setIdentityZone(idZone2);
        ResponseEntity<Map<String,String>> response2 = client.exchange(
                serverRunning.getUrl("/identity-zones/{id}"), 
                HttpMethod.PUT,
                new HttpEntity<IdentityZoneCreationRequest>(request2), 
                new ParameterizedTypeReference<Map<String,String>>() {}, 
                id2);
        assertEquals(HttpStatus.CONFLICT, response2.getStatusCode());
        Assert.assertTrue(response2.getBody().get("error_description").toLowerCase().contains("subdomain"));
    }
    
    static class IdentityClient extends ClientCredentialsResourceDetails {
        public IdentityClient(Object target) {
            IdentityZoneEndpointsIntegrationTests test = (IdentityZoneEndpointsIntegrationTests) target;
            ClientCredentialsResourceDetails resource = test.testAccounts.getClientCredentialsResource(
                            new String[] {"zones.create"}, "identity", "identitysecret");
            setClientId(resource.getClientId());
            setClientSecret(resource.getClientSecret());
            setId(getClientId());
            setAccessTokenUri(test.serverRunning.getAccessTokenUri());
        }
    }
    
}
