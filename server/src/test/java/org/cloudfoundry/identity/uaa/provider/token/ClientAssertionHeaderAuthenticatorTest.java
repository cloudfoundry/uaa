package org.cloudfoundry.identity.uaa.provider.token;

import java.util.Map;

import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.security.core.AuthenticationException;

public class ClientAssertionHeaderAuthenticatorTest {
    private final static String TENANT_ID = "t10";
    private final static String DEVICE_ID = "d10";
    private Long currentTimeSeconds = System.currentTimeMillis() / 1000L;
    
    @Test
    public void testSuccess() {
        String header = new MockClientAssertionHeader().mockSignedHeader(currentTimeSeconds,
                DEVICE_ID, TENANT_ID);
        ClientAssertionHeaderAuthenticator headerAuthenticator = new ClientAssertionHeaderAuthenticator();
        Map<String, Object> claims = headerAuthenticator.authenticate(header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        Assert.assertEquals(DEVICE_ID, claims.get(ClaimConstants.SUB));
        Assert.assertEquals(TENANT_ID, claims.get(ClaimConstants.TENANT_ID));
    }
    
    @Test(expected=AuthenticationException.class)
    public void testIncorrectSigningKey() {
        String header = new MockClientAssertionHeader().mockIncorrectlySignedHeader(DEVICE_ID, TENANT_ID);
        ClientAssertionHeaderAuthenticator headerAuthenticator = new ClientAssertionHeaderAuthenticator();
        headerAuthenticator.authenticate(header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
    }    

    @Test(expected=AuthenticationException.class)
    public void testHeaderTTLExpired() throws InterruptedException {
        String header = new MockClientAssertionHeader().mockSignedHeader(currentTimeSeconds,
                DEVICE_ID, TENANT_ID);

        //set TTL for header to 1 second
        ClientAssertionHeaderAuthenticator headerAuthenticator = new ClientAssertionHeaderAuthenticator(1);
        //wait for header to expire
        Thread.sleep(2000);

        headerAuthenticator.authenticate(header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
    }
    
    @Test
    public void testIatClaimTimeSkew() throws InterruptedException {
        try {
            String header = new MockClientAssertionHeader().mockSignedHeader(currentTimeSeconds - 6, DEVICE_ID, TENANT_ID);
            ClientAssertionHeaderAuthenticator headerAuthenticator = new ClientAssertionHeaderAuthenticator();
            headerAuthenticator.authenticate(header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
            Assert.fail("authenticate did not fail when iat is skewed by more than 5 seconds");
        } catch (AuthenticationException e) {
            //expected
        }
        
        currentTimeSeconds = System.currentTimeMillis() / 1000L;
        try {
            String header = new MockClientAssertionHeader().mockSignedHeader(currentTimeSeconds + 6, DEVICE_ID, TENANT_ID);
            ClientAssertionHeaderAuthenticator headerAuthenticator = new ClientAssertionHeaderAuthenticator();
            headerAuthenticator.authenticate(header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
            Assert.fail("authenticate did not fail when iat is skewed by more than 5 seconds");
        } catch (AuthenticationException e) {
            //expected
        }

        currentTimeSeconds = System.currentTimeMillis() / 1000L;
        String header = new MockClientAssertionHeader().mockSignedHeader(currentTimeSeconds + 3, DEVICE_ID, TENANT_ID);
        ClientAssertionHeaderAuthenticator headerAuthenticator = new ClientAssertionHeaderAuthenticator();
        Assert.assertNotNull(headerAuthenticator.authenticate(header, MockKeyProvider.DEVICE1_PUBLIC_KEY));
        
        currentTimeSeconds = System.currentTimeMillis() / 1000L;
        header = new MockClientAssertionHeader().mockSignedHeader(currentTimeSeconds - 3, DEVICE_ID, TENANT_ID);
        headerAuthenticator = new ClientAssertionHeaderAuthenticator();
        Assert.assertNotNull(headerAuthenticator.authenticate(header, MockKeyProvider.DEVICE1_PUBLIC_KEY));
    }

    @Test(expected=AuthenticationException.class)
    public void testIatClaimAbsent() {
        String header = new MockClientAssertionHeader().mockSignedHeader(null, DEVICE_ID, TENANT_ID);
        ClientAssertionHeaderAuthenticator headerAuthenticator = new ClientAssertionHeaderAuthenticator();
        headerAuthenticator.authenticate(header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
    }

    @Test(expected=AuthenticationException.class)
    public void testTenantIdClaimAbsent() {
        String header = new MockClientAssertionHeader().mockSignedHeader(currentTimeSeconds, DEVICE_ID, null);
        ClientAssertionHeaderAuthenticator headerAuthenticator = new ClientAssertionHeaderAuthenticator();
        headerAuthenticator.authenticate(header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
    }

    @Test(expected=AuthenticationException.class)
    public void testSubClaimAbsent() {
        String header = new MockClientAssertionHeader().mockSignedHeader(currentTimeSeconds, null, TENANT_ID);
        ClientAssertionHeaderAuthenticator headerAuthenticator = new ClientAssertionHeaderAuthenticator();
        headerAuthenticator.authenticate(header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
    }
}
