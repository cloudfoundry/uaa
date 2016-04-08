package org.cloudfoundry.identity.uaa.provider.token;

import static org.mockito.Mockito.when;
import static org.springframework.security.jwt.codec.Codecs.concat;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;

import org.bouncycastle.openssl.PEMWriter;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.codec.Codecs;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;
import com.ge.predix.pki.device.spi.PublicKeyNotFoundException;

public class JwtBearerAssertionTokenAuthenticatorTest {

    private final static Charset UTF8 = Charset.forName("UTF-8");
    private final static String TENANT_ID = "t10";
    private final static String DEVICE_1_ID = MockKeyProvider.DEVICE_1;
    private final static String AUDIENCE = "http://localhost:8080/uaa/oauth/token";
    private static final String DEVICE_2_ID = MockKeyProvider.DEVICE_2;

    @InjectMocks
    private final JwtBearerAssertionTokenAuthenticator tokenAuthenticator = new JwtBearerAssertionTokenAuthenticator(
            AUDIENCE);

    @Mock
    private ClientDetailsService clientDetailsService;

    @Before
    public void beforeMethod() {
        MockitoAnnotations.initMocks(this);
        this.tokenAuthenticator.setClientPublicKeyProvider(new MockKeyProvider());
        when(this.clientDetailsService.loadClientByClientId(DEVICE_1_ID))
                .thenReturn(new BaseClientDetails(DEVICE_1_ID, null, null, null, null, null));
    }

    @Test
    public void testSuccess() {
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_ID, System.currentTimeMillis() - 240000L,
                600, TENANT_ID, AUDIENCE);
        String header = new MockClientAssertionHeader().mockSignedHeader(DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Authentication authn = this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        Assert.assertEquals(DEVICE_1_ID, authn.getPrincipal());
        Assert.assertEquals(true, authn.isAuthenticated());
    }

    @Test
    public void testVerificationWithoutJwtHelper() throws Exception {
        final byte[] PERIOD = Codecs.utf8Encode(".");

        byte[] header = Codecs.b64UrlEncode(Codecs.utf8Encode("{\"alg\":\"RS256\"}"));

        long iat = System.currentTimeMillis();
        long expiration = iat + 300000;
        String claimStr = JsonUtils.writeValueAsString(MockAssertionToken.createClaims(DEVICE_1_ID,
                AUDIENCE, System.currentTimeMillis(), expiration / 1000, "tenantId"));
        byte[] claims = Codecs.b64UrlEncode(Codecs.utf8Encode(claimStr));

        byte[] contentToSign = concat(header, PERIOD, claims);

        Signature signer = Signature.getInstance("SHA256withRSA");
        KeyPair keypair = getNewRsaKeyPair();
        signer.initSign(keypair.getPrivate());
        signer.update(contentToSign);
        byte[] jwtSignature = Codecs.b64UrlEncode(signer.sign());

        byte[] token = concat(contentToSign, PERIOD, jwtSignature);

        this.tokenAuthenticator.setClientPublicKeyProvider(new TestKeyProvider(keypair));
        this.tokenAuthenticator.authenticate(Codecs.utf8Decode(token));
    }

    private KeyPair getNewRsaKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
        keygen.initialize(2048);
        return keygen.generateKeyPair();
    }

    private static class TestKeyProvider implements DevicePublicKeyProvider {
        private final KeyPair testPair;

        TestKeyProvider(final KeyPair pair) {
            this.testPair = pair;
        }
        
        @Override
        public String getPublicKey(final String tenantId, final String deviceId) throws PublicKeyNotFoundException {
            try {
                byte[] publicKey = Base64.getUrlEncoder().encode(getPEMPublicKey(this.testPair.getPublic()));
                return new String(publicKey, UTF8);
            } catch (IOException e) {
                throw new PublicKeyNotFoundException(e);
            }
        }

        private static byte[] getPEMPublicKey(PublicKey publicKey) throws IOException {
            PEMWriter pemWriter = null;
            StringWriter stringWriter = null;
            try {
                stringWriter = new StringWriter();
                pemWriter = new PEMWriter(stringWriter);
                pemWriter.writeObject(publicKey);
                pemWriter.close();
                return stringWriter.toString().getBytes();
            } finally {
                stringWriter.close();
            }
        }
    }

    @Test(expected = AuthenticationException.class)
    public void testNonExistentClient() {
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE);
        
        //remove d1 client from mock
        when(this.clientDetailsService.loadClientByClientId(DEVICE_1_ID))
        .thenReturn(null);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        
        this.tokenAuthenticator.authenticate(token);
    }

    @Test(expected = AuthenticationException.class)
    public void testInvalidSigningKey() {
        MockAssertionToken testTokenUtil = new MockAssertionToken(MockKeyProvider.INCORRECT_TOKEN_SIGNING_KEY);
        String token = testTokenUtil.mockAssertionToken(DEVICE_1_ID, System.currentTimeMillis() - 240000, 600, TENANT_ID,
                AUDIENCE);
        this.tokenAuthenticator.authenticate(token);
    }

    @Test(expected = AuthenticationException.class)
    public void testMissingToken() {
        this.tokenAuthenticator.authenticate(null);
    }

    @Test(expected = AuthenticationException.class)
    public void testExpiredToken() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockAssertionToken(DEVICE_1_ID, System.currentTimeMillis() - 240000, 60, TENANT_ID,
                AUDIENCE);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        this.tokenAuthenticator.authenticate(token);
    }
    
    @Test(expected = AuthenticationException.class)
    public void testTokenWithNoExpClaim() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        //create token with no exp claim
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(DEVICE_1_ID, 0, 0,
                TENANT_ID, AUDIENCE, null);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        this.tokenAuthenticator.authenticate(token);
    }

    @Test(expected = AuthenticationException.class)
    public void testAudienceMismatch() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockAssertionToken(DEVICE_1_ID, System.currentTimeMillis() - 240000, 600, TENANT_ID,
                "https://zone1.wrong-uaa.com");
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        this.tokenAuthenticator.authenticate(token);
    }

    @Test(expected = AuthenticationException.class)
    public void testInvalidExpirationFormatString() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(DEVICE_1_ID,
                System.currentTimeMillis() - 240000, 600, TENANT_ID, AUDIENCE, "invalid-expiration-as-string");
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        this.tokenAuthenticator.authenticate(token);
    }

    @Test(expected = AuthenticationException.class)
    public void testInvalidExpirationFormatNegativeNumber() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(DEVICE_1_ID,
                System.currentTimeMillis() - 240000, 600, TENANT_ID, AUDIENCE, -1);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        this.tokenAuthenticator.authenticate(token);
    }

    @Test(expected = AuthenticationException.class)
    public void testInvalidExpirationFormatInRangeNegativeLong() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(DEVICE_1_ID,
                System.currentTimeMillis() - 240000, 600, TENANT_ID, AUDIENCE, -9223372036854775808L);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        this.tokenAuthenticator.authenticate(token);
    }

    @Test(expected = AuthenticationException.class)
    public void testInvalidExpirationFormatOutofRangeLong() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(DEVICE_1_ID,
                System.currentTimeMillis() - 240000, 600, TENANT_ID, AUDIENCE, "9223372036854775808");
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        this.tokenAuthenticator.authenticate(token);
    }

    @Test(expected = AuthenticationException.class)
    public void testMissingClientAssertionHeader() {
        this.tokenAuthenticator.authenticate("sometoken", null, MockKeyProvider.DEVICE1_PUBLIC_KEY);
    }

    @Test(expected = AuthenticationException.class)
    public void testPublicKeyNotFound() {
        class NotFoundKeyProvider implements DevicePublicKeyProvider {
            @Override
            public String getPublicKey(final String tenantId, final String deviceId) throws PublicKeyNotFoundException {
                throw new PublicKeyNotFoundException();
            }

        }
        String header = new MockClientAssertionHeader().mockSignedHeader(DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientPublicKeyProvider(new NotFoundKeyProvider());
        Assert.assertNotNull(this.tokenAuthenticator.authenticate("sometoken", header, MockKeyProvider.DEVICE1_PUBLIC_KEY));
    }

    @Test(expected = AuthenticationException.class)
    public void testPublicKeyIsNull() {
        class NullKeyProvider implements DevicePublicKeyProvider {
            @Override
            public String getPublicKey(final String tenantId, final String deviceId) throws PublicKeyNotFoundException {
                return null;
            }

        }
        String header = new MockClientAssertionHeader().mockSignedHeader(DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientPublicKeyProvider(new NullKeyProvider());
        Assert.assertNotNull(this.tokenAuthenticator.authenticate("sometoken", header, MockKeyProvider.DEVICE1_PUBLIC_KEY));
    }

    @Test(expected = AuthenticationException.class)
    public void testPublicKeyProviderIsNull() {
        String header = new MockClientAssertionHeader().mockSignedHeader(DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientPublicKeyProvider(null);
        Assert.assertNotNull(this.tokenAuthenticator.authenticate("sometoken", header, MockKeyProvider.DEVICE1_PUBLIC_KEY));
    }

    /**
     * A
     * d1 authenticates w/  2-way TLS to F5.  proxy
     * sends jwt-asssertion (iss: d2), signed by d1 
     */

    
    /**
     * d1 authenticates w/  2-way TLS to F5.  (clientAssertionHeader = (d1, tenant_id)
     * sends jwt-asssertion (sub: d2), signed by d1 
     */
    @Test(expected = AuthenticationException.class)
    public void testDeviceSpoofWithIncorrectSubjectClaim() throws Exception {
        KeyPair proxyKeyPair = getNewRsaKeyPair();
        // assertion header (d2, tenant_id) signed by proxy
        String device2SignedHeader = new MockClientAssertionHeader((RSAPrivateKey) proxyKeyPair.getPrivate())
                .mockSignedHeader(DEVICE_1_ID, TENANT_ID);
        String proxyPublicKey = new String(TestKeyProvider.getPEMPublicKey(proxyKeyPair.getPublic()), UTF8);

        // setup test key provider
        this.tokenAuthenticator.setClientPublicKeyProvider(new MockKeyProvider());

        // provision client id d2 in mock
        when(this.clientDetailsService.loadClientByClientId(DEVICE_2_ID))
        .thenReturn(new BaseClientDetails(DEVICE_2_ID, null, null, null, null, null));
        
        //jwt assertion (sub: d2) , signed by d1
        String device1token = new MockAssertionToken().mockAssertionToken(DEVICE_2_ID, System.currentTimeMillis() - 240000L,
                600, TENANT_ID, AUDIENCE);

        
        this.tokenAuthenticator.authenticate(device1token, device2SignedHeader, proxyPublicKey);
    }
    
}
