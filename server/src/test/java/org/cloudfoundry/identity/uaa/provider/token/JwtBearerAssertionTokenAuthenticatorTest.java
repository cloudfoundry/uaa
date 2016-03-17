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

    //private final static String TENANT_ID = "tenant_id";
    private final static String TENANT_ID = "t10";
    private final static String ISSUER_ID = "d10";
    //private final static String ISSUER_ID = "jb-machine-client";
//    private final static String AUDIENCE =  "https://zone1.uaa.ge.com/oauth/token";
    private final static String AUDIENCE =  "http://localhost:8080/uaa/oauth/token";
    
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
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000L,
                600, TENANT_ID, AUDIENCE);
        //String token = "eyAiYWxnIjogIlJTMjU2IiB9.eyAidGVuYW50X2lkIjogIjc4YTBmOWRjLWUyNzEtMTFlNS1hOWRhLWEwOTk5YjEwNDc3MyIsImF1ZCI6ICJodHRwOi8vbG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIiwic3ViIjogIjRkY2VmNDAyLWUyNzEtMTFlNS04MjgxLWEwOTk5YjEwNDc3MyIsImlzcyI6ICJmNV9kZXZfY2xpZW50IiwiZXhwIjogIjE1NTc5ODk3MjcifQ==.MIUNGfWIDWjauNMgsc0mlYZ61gVJJEqqNYX0ovV09L9BKnxqfEz4busj0umSJhCw2AoI4N9YWo1VzqQdPYskO_YR4oqnC6gmKa83ZfObkbPg0Ea9sn4XVee-d2-RGhyuCZd8swLNX6sGLCJ1U-l4qGmq3_dXzkMe_lwcrNUSkrUagVI-cPCPUH3l_g3pgm66xDOX2z1N06fDmos2JOiDWJtUn0W54Zkh9MDqd0r-Sl_ykS-OOQDByfNs6XDidRFTJ5zNjigioVA8lgnUiQCSConFlZZo-S_16eKuq7Hx93YL6tKnv_pmr9GRmNEmca-LJ5MS_1YyqRY0WGU3XL6ZWA==";
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

    @Test(expected=AuthenticationException.class)
    public void testInvalidExpirationFormatString() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE, "invalid-expiration-as-string");
        tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        tokenAuthenticator.authenticate(token);
    }

    @Test(expected=AuthenticationException.class)
    public void testInvalidExpirationFormatNegativeNumber() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE, -1);
        tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        tokenAuthenticator.authenticate(token);
    }

    @Test(expected=AuthenticationException.class)
    public void testInvalidExpirationFormatInRangeNegativeLong() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE, -9223372036854775808L);
        tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        tokenAuthenticator.authenticate(token);
    }

    @Test(expected=AuthenticationException.class)
    public void testInvalidExpirationFormatOutofRangeLong() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE, "9223372036854775808");
        tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        tokenAuthenticator.authenticate(token);
    }
}
