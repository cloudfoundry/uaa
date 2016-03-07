package org.cloudfoundry.identity.uaa.provider.token;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.core.AuthenticationException;

public class JwtBearerAssertionTokenAuthenticatorTest {

    private final static String TENANT_ID = "tenant_id";
    private final static String ISSUER_ID = "jb-machine-client";
    private final static String AUDIENCE =  "https://zone1.uaa.ge.com/oauth/token";
    
    @InjectMocks
    private JwtBearerAssertionTokenAuthenticator tokenAuthenticator = new JwtBearerAssertionTokenAuthenticator(AUDIENCE);

    @Mock
    private ClientDetailsService clientDetailsService;
    
    @Before
    public void beforeMethod() {
        MockitoAnnotations.initMocks(this);
        this.tokenAuthenticator.setClientPublicKeyProvider(new MockPublicKeyProvider());
        when(clientDetailsService.loadClientByClientId(anyString()))
        .thenReturn(new BaseClientDetails(ISSUER_ID, null, null, null, null, null));
    }
    
    @Test
    public void testSuccess() {
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE);
        System.out.println("Token: " + token);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assert.assertNotNull(tokenAuthenticator.authenticate(token));
    }
    
    @Test(expected=AuthenticationException.class)
    public void testNonExistentClient() {
        String token = new MockAssertionToken().mockAssertionToken("nonexistent-client", System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE);
        when(clientDetailsService.loadClientByClientId(anyString())).thenReturn(null);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        tokenAuthenticator.authenticate(token);
    }

    @Test(expected=AuthenticationException.class)
    public void testInvalidSigningKey() {
        MockAssertionToken testTokenUtil = new MockAssertionToken(TestKeys.INCORRECT_TOKEN_SIGNING_KEY);
        String token = testTokenUtil.mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE);
        tokenAuthenticator.authenticate(token);
    }

    @Test(expected=AuthenticationException.class)
    public void testMissingToken() {
        tokenAuthenticator.authenticate(null);
    }

    @Test(expected=AuthenticationException.class)
    public void testExpiredToken() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                60, TENANT_ID, AUDIENCE);
        tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        tokenAuthenticator.authenticate(token);
    }

    @Test(expected=AuthenticationException.class)
    public void testAudienceMismatch() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, "https://zone1.wrong-uaa.com");
        tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        tokenAuthenticator.authenticate(token);
    }

}
