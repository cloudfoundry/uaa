package org.cloudfoundry.identity.uaa.provider.token;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.jwt.codec.Codecs.concat;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;

import org.bouncycastle.openssl.PEMWriter;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.codec.Codecs;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;
import com.ge.predix.pki.device.spi.PublicKeyNotFoundException;

public class JwtBearerAssertionTokenAuthenticatorTest {
    
    private final static Charset UTF8 = Charset.forName("UTF-8");
    private final static String TENANT_ID = "t10";
    private final static String ISSUER_ID = "d10";
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
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assert.assertNotNull(tokenAuthenticator.authenticate(token));
    }
    
    @Test
    public void testVerificationWithoutJwtHelper() throws Exception
    {
        final byte[] PERIOD = Codecs.utf8Encode(".");
        
        byte[] header = Codecs.b64UrlEncode(Codecs.utf8Encode("{\"alg\":\"RS256\"}"));
        
        long iat = System.currentTimeMillis(); 
        long expiration = iat + 300000 ;
        String claimStr = JsonUtils.writeValueAsString(MockAssertionToken
                .createClaims(ISSUER_ID, "test-userid", AUDIENCE, 
                        System.currentTimeMillis(), expiration/1000 , "tenantId"));
        byte[] claims = Codecs.b64UrlEncode(Codecs.utf8Encode(claimStr));
        
        byte[] contentToSign = concat(header, PERIOD, claims);
        
        Signature signer = Signature.getInstance("SHA256withRSA");
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA","SunRsaSign");
        keygen.initialize(2048);
        KeyPair keypair = keygen.generateKeyPair();
        signer.initSign(keypair.getPrivate());
        signer.update(contentToSign);
        byte[] jwtSignature = Codecs.b64UrlEncode(signer.sign());
        
        byte[] token = concat(contentToSign, PERIOD, jwtSignature);
        
        this.tokenAuthenticator.setClientPublicKeyProvider(new TestKeyProvider(keypair));
        this.tokenAuthenticator.authenticate(Codecs.utf8Decode(token));
    }
    
    private static class TestKeyProvider implements DevicePublicKeyProvider {
        private KeyPair testPair;
        
        TestKeyProvider(KeyPair pair) {
            this.testPair = pair;
        }
        
        @Override
        public String getPublicKey(String tenantId, String deviceId) throws PublicKeyNotFoundException{
            StringWriter stringWriter = new StringWriter();
            PEMWriter pemWriter = new PEMWriter(stringWriter);  
            try {
                pemWriter.writeObject(testPair.getPublic());
                pemWriter.close();
            } catch(IOException e){

            }
            byte[] publicKey = stringWriter.toString().getBytes();
            return new String(Base64.getUrlEncoder().encode(publicKey), UTF8);
        }
        
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
