package org.cloudfoundry.identity.uaa.provider.token;

import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;
import com.ge.predix.pki.device.spi.PublicKeyNotFoundException;
import org.bouncycastle.openssl.PEMWriter;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.KeyProviderConfig;
import org.cloudfoundry.identity.uaa.provider.KeyProviderProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.apache.commons.lang.NotImplementedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.codec.Codecs;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;

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
import java.util.Date;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.jwt.codec.Codecs.concat;

public class JwtBearerAssertionTokenAuthenticatorTest {

    private final static Charset UTF8 = Charset.forName("UTF-8");
    private final static String TENANT_ID = "t10";
    private final static String DEVICE_1_ID = MockKeyProvider.DEVICE_1;
    private final static String DEVICE_1_CLIENT_ID = "c1";
    private final static String AUDIENCE = "http://localhost:8080/uaa/oauth/token";
    private static final String DEVICE_2_ID = MockKeyProvider.DEVICE_2;

    private final JwtBearerAssertionTokenAuthenticator tokenAuthenticator = new JwtBearerAssertionTokenAuthenticator(
            AUDIENCE, 15);

    private ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);
    
    private long currentTimeSecs;
    private MockKeyProvider mockPublicKeyProvider;
    private KeyProviderProvisioning keyProviderConfigProvisioner = Mockito.mock(KeyProviderProvisioning.class);
    private TokenGranter mockTokenGranter = Mockito.mock(ClientCredentialsTokenGranter.class);

    @BeforeEach
    public void beforeMethod() {
        mockPublicKeyProvider = new MockKeyProvider();
        this.tokenAuthenticator.setClientPublicKeyProvider(mockPublicKeyProvider);
        this.tokenAuthenticator.setKeyProviderProvisioning(keyProviderConfigProvisioner);
        this.tokenAuthenticator.setDcsEndpointTokenGranter(mockTokenGranter);
        BaseClientDetails testUaaClient = new BaseClientDetails(DEVICE_1_CLIENT_ID, null, null, null, null, null);
        testUaaClient.addAdditionalInformation(ClientConstants.ALLOWED_DEVICE_ID, DEVICE_1_ID);
        when(this.clientDetailsService.loadClientByClientId(DEVICE_1_CLIENT_ID)).thenReturn(testUaaClient);
        this.currentTimeSecs =  System.currentTimeMillis()/1000;
    }

    @Test
    public void testSuccessWithKeyProvider() {
        long currentTime = System.currentTimeMillis();
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                currentTime, 600, TENANT_ID, AUDIENCE);
        BaseClientDetails dcsClient = new BaseClientDetails();
        dcsClient.setClientId("dcsClient");
        KeyProviderConfig mockConfig = new KeyProviderConfig(dcsClient.getClientId(), "test-dcs-zone-guid");
        when(keyProviderConfigProvisioner.findActive()).thenReturn(mockConfig);
        when(mockTokenGranter.grant(eq(GRANT_TYPE_CLIENT_CREDENTIALS), any(TokenRequest.class))).thenReturn(getMockToken());
        when(this.clientDetailsService.loadClientByClientId(dcsClient.getClientId())).thenReturn(dcsClient);
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);

        Authentication authn = this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);

        Assert.assertEquals(DEVICE_1_CLIENT_ID, authn.getPrincipal());
        Assert.assertEquals(true, authn.isAuthenticated());
        Assert.assertEquals("test-dcs-zone-guid", mockPublicKeyProvider.receivedZoneId);
    }

    @Test
    public void testKeyProviderConfigWithNullClientIdFallsBackToGlobalConfig() {
        long currentTime = System.currentTimeMillis();
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                currentTime, 600, TENANT_ID, AUDIENCE);
        KeyProviderConfig mockConfig = new KeyProviderConfig(null, "test-dcs-zone-guid");
        when(keyProviderConfigProvisioner.findActive()).thenReturn(mockConfig);
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);

        Authentication authn = this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);

        verify(mockTokenGranter, never()).grant(eq(GRANT_TYPE_CLIENT_CREDENTIALS), any());
        Assert.assertEquals(DEVICE_1_CLIENT_ID, authn.getPrincipal());
        Assert.assertEquals(true, authn.isAuthenticated());
        Assert.assertEquals("", mockPublicKeyProvider.receivedZoneId);
    }

    @Test
    public void testKeyProviderConfigWithNonExistentClientIdFallsBackToGlobalConfig() {
        long currentTime = System.currentTimeMillis();
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                currentTime, 600, TENANT_ID, AUDIENCE);
        KeyProviderConfig mockConfig = new KeyProviderConfig("not-a-real-client", "test-dcs-zone-guid");
        when(keyProviderConfigProvisioner.findActive()).thenReturn(mockConfig);
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);

        Authentication authn = this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);

        verify(mockTokenGranter, never()).grant(eq(GRANT_TYPE_CLIENT_CREDENTIALS), any());
        Assert.assertEquals(DEVICE_1_CLIENT_ID, authn.getPrincipal());
        Assert.assertEquals(true, authn.isAuthenticated());
        Assert.assertEquals("", mockPublicKeyProvider.receivedZoneId);
    }

    private OAuth2AccessToken getMockToken() {
        return new OAuth2AccessToken() {
            @Override
            public Map<String, Object> getAdditionalInformation() {
                return null;
            }

            @Override
            public Set<String> getScope() {
                return null;
            }

            @Override
            public OAuth2RefreshToken getRefreshToken() {
                return null;
            }

            @Override
            public String getTokenType() {
                return null;
            }

            @Override
            public boolean isExpired() {
                return false;
            }

            @Override
            public Date getExpiration() {
                return null;
            }

            @Override
            public int getExpiresIn() {
                return 0;
            }

            @Override
            public String getValue() {
                return "tokenstring";
            }
        };
    }

    @Test
    public void testNoKeyProviderConfig() {
        long currentTime = System.currentTimeMillis();
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                currentTime, 600, TENANT_ID, AUDIENCE);
        when(keyProviderConfigProvisioner.findActive()).thenReturn(null);
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);

        Authentication authn = this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);

        Assert.assertEquals(DEVICE_1_CLIENT_ID, authn.getPrincipal());
        Assert.assertEquals(true, authn.isAuthenticated());
        Assert.assertEquals("", mockPublicKeyProvider.receivedZoneId);
    }

    @Test
    public void testSuccessWithAudienceAsArray() {
        long currentTime = System.currentTimeMillis();
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                currentTime, 600, TENANT_ID, new String[] {"https://other-aud.com/path", AUDIENCE});
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);

        Authentication authn = this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);

        Assert.assertEquals(DEVICE_1_CLIENT_ID, authn.getPrincipal());
        Assert.assertEquals(true, authn.isAuthenticated());
    }

    @Test
    public void testInvalidAudienceAsArray() {
        long currentTime = System.currentTimeMillis();
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                currentTime, 600, TENANT_ID, new String[] {"https://other-aud.com/path"});
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        });
    }

    @Test
    public void testInvalidAudienceEmptyArray() {
        long currentTime = System.currentTimeMillis();
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                currentTime, 600, TENANT_ID, new String[] {});
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        });
    }

    @Test
    public void testInvalidAudienceType() {
        long currentTime = System.currentTimeMillis();
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                currentTime, 600, TENANT_ID, 1);
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        });
    }

    // c1.allowed_device_id is not set
    @Test
    public void testNoAllowedDeviceIdSet() {
        long currentTime = System.currentTimeMillis();
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                currentTime, 600, TENANT_ID, AUDIENCE);
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        
        //allowed_device_id not set
        when(this.clientDetailsService.loadClientByClientId(DEVICE_1_CLIENT_ID)) 
            .thenReturn(new BaseClientDetails(DEVICE_1_CLIENT_ID, null, null, null, null, null));
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);

        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        });
    }

    // c1.allowed_device_id is set to null
    @Test
    public void testAllowedDeviceIdNull() {
        long currentTime = System.currentTimeMillis();
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                currentTime, 600, TENANT_ID, AUDIENCE);
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        
        //allowed_device_id is set to null
        BaseClientDetails testUaaClient = new BaseClientDetails(DEVICE_1_CLIENT_ID, null, null, null, null, null);
        testUaaClient.addAdditionalInformation(ClientConstants.ALLOWED_DEVICE_ID, null);
        
        when(this.clientDetailsService.loadClientByClientId(DEVICE_1_CLIENT_ID)) 
            .thenReturn(new BaseClientDetails(DEVICE_1_CLIENT_ID, null, null, null, null, null));
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);

        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        });
    }

    // c1.allowed_device_id is set to empty string
    @Test
    public void testAllowedDeviceIdEmpty() {
        long currentTime = System.currentTimeMillis();
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                currentTime, 600, TENANT_ID, AUDIENCE);
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        
        //allowed_device_id is set to null
        BaseClientDetails testUaaClient = new BaseClientDetails(DEVICE_1_CLIENT_ID, null, null, null, null, null);
        testUaaClient.addAdditionalInformation(ClientConstants.ALLOWED_DEVICE_ID, "");
        
        when(this.clientDetailsService.loadClientByClientId(DEVICE_1_CLIENT_ID)) 
            .thenReturn(new BaseClientDetails(DEVICE_1_CLIENT_ID, null, null, null, null, null));
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);

        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        });
    }

    //c1.allowed_device_id != sub claim in jwt assertion 
    @Test
    public void testUnauthorizedDeviceId() {
        long currentTime = System.currentTimeMillis();
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                currentTime, 600, TENANT_ID, AUDIENCE);
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        
        //set allowed_device_id to  "non-matching-allowed-device"
        BaseClientDetails testUaaClient = new BaseClientDetails(DEVICE_1_CLIENT_ID, null, null, null, null, null);
        testUaaClient.addAdditionalInformation(ClientConstants.ALLOWED_DEVICE_ID, "non-matching-allowed-device");
        when(this.clientDetailsService.loadClientByClientId(DEVICE_1_CLIENT_ID)).thenReturn(testUaaClient);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);

        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticate(token, header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        });
    }

    @Test
    public void testVerificationWithoutJwtHelper() throws Exception {
        final byte[] PERIOD = Codecs.utf8Encode(".");

        byte[] header = Codecs.b64UrlEncode(Codecs.utf8Encode("{\"alg\":\"RS256\"}"));

        long iat = System.currentTimeMillis();
        long expiration = iat + 300000;
        String claimStr = JsonUtils.writeValueAsString(MockAssertionToken.createClaims(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
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
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        this.tokenAuthenticator.authenticateWithoutClientAssertionHeader(Codecs.utf8Decode(token));
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
        public String getPublicKey(final String tenantId, final String deviceId, final String predixZoneId) throws PublicKeyNotFoundException {
            try {
                byte[] publicKey = Base64.getUrlEncoder().encode(getPEMPublicKey(this.testPair.getPublic()));
                return new String(publicKey, UTF8);
            } catch (IOException e) {
                throw new PublicKeyNotFoundException(e);
            }
        }

        @Override
        public String getPublicKeyWithToken(final String tenantId, final String deviceId, final String predixZoneId, final String token) throws PublicKeyNotFoundException {
            //TODO make sure to implement this method for testing when DCS changes are made to JwtBearerAssertionTokenAuthenticator is changed
            throw new NotImplementedException();
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

    @Test
    public void testNonExistentClient() {
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                System.currentTimeMillis(), 600, TENANT_ID, AUDIENCE);
        
        //remove d1 client from mock
        when(this.clientDetailsService.loadClientByClientId(DEVICE_1_CLIENT_ID))
        .thenReturn(null);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticateWithoutClientAssertionHeader(token);
        });
    }

    @Test
    public void testInvalidClientException() {
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                System.currentTimeMillis(), 600, TENANT_ID, AUDIENCE);

        when(this.clientDetailsService.loadClientByClientId(DEVICE_1_CLIENT_ID)).thenThrow(
                new InvalidClientException("Requested client is invalid"));
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);

        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticateWithoutClientAssertionHeader(token);
        });
    }

    @Test
    public void testInvalidSigningKey() {
        MockAssertionToken testTokenUtil = new MockAssertionToken(MockKeyProvider.INCORRECT_TOKEN_SIGNING_KEY);
        String token = testTokenUtil.mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID, System.currentTimeMillis(), 600,
                TENANT_ID, AUDIENCE);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticateWithoutClientAssertionHeader(token);
        });
    }

    @Test
    public void testMissingToken() {
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticateWithoutClientAssertionHeader(null);
        });
    }

    @Test
    public void testExpiredToken() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID, System.currentTimeMillis() - 240000, 60,
                TENANT_ID, AUDIENCE);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticateWithoutClientAssertionHeader(token);
        });
    }
    
    @Test
    public void testTokenWithNoExpClaim() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        //create token with no exp claim
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID, 0, TENANT_ID,
                AUDIENCE, null);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticateWithoutClientAssertionHeader(token);
        });
    }

    @Test
    public void testAudienceMismatch() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID, System.currentTimeMillis(), 600,
                TENANT_ID, "https://zone1.wrong-uaa.com");
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticateWithoutClientAssertionHeader(token);
        });
    }

    @Test
    public void testInvalidExpirationFormatString() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                System.currentTimeMillis(), TENANT_ID, AUDIENCE, "invalid-expiration-as-string");
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticateWithoutClientAssertionHeader(token);
        });
    }

    @Test
    public void testInvalidExpirationFormatNegativeNumber() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                System.currentTimeMillis(), TENANT_ID, AUDIENCE, -1);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticateWithoutClientAssertionHeader(token);
        });
    }

    @Test
    public void testExpirationClaimNegativeLong() {
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                System.currentTimeMillis(), TENANT_ID, AUDIENCE, -9223372036854775808L);
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticateWithoutClientAssertionHeader(token);
        });
    }

    //RFC7519 requires exp value to be 'NumericDate' - A JSON numeric value representing the number of seconds since..
    @Test
    public void testInvalidExpirationJsonString() {
        long currentTime = System.currentTimeMillis();
        MockAssertionToken testTokenUtil = new MockAssertionToken();
        String token = testTokenUtil.mockInvalidExpirationAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_1_ID,
                 currentTime, TENANT_ID, AUDIENCE, String.valueOf(currentTime + 60));
        this.tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticateWithoutClientAssertionHeader(token);
        });
    }

    @Test
    public void testMissingClientAssertionHeader() {
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticate("sometoken", null, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        });
    }

    @Test
    public void testPublicKeyNotFound() {
        class NotFoundKeyProvider implements DevicePublicKeyProvider {
            @Override
            public String getPublicKey(final String tenantId, final String deviceId, final String predixZoneId) throws PublicKeyNotFoundException {
                throw new PublicKeyNotFoundException();
            }

            @Override
            public String getPublicKeyWithToken(final String tenantId, final String deviceId, final String predixZoneId, final String token) throws PublicKeyNotFoundException {
                throw new PublicKeyNotFoundException();
            }

        }
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientPublicKeyProvider(new NotFoundKeyProvider());
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticate("sometoken", header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        });
    }

    @Test
    public void testPublicKeyIsNull() {
        class NullKeyProvider implements DevicePublicKeyProvider {
            @Override
            public String getPublicKey(final String tenantId, final String deviceId, final String predixZoneId) throws PublicKeyNotFoundException {
                return null;
            }

            @Override
            public String getPublicKeyWithToken(final String tenantId, final String deviceId, final String predixZoneId,  final String token) throws PublicKeyNotFoundException {
                return null;
            }

        }
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientPublicKeyProvider(new NullKeyProvider());
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticate("sometoken", header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        });
    }

    @Test
    public void testPublicKeyProviderIsNull() {
        String header = new MockClientAssertionHeader().mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        this.tokenAuthenticator.setClientPublicKeyProvider(null);
        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticate("sometoken", header, MockKeyProvider.DEVICE1_PUBLIC_KEY);
        });
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
    @Test
    public void testDeviceSpoofWithIncorrectSubjectClaim() throws Exception {
        KeyPair proxyKeyPair = getNewRsaKeyPair();
        // assertion header (d2, tenant_id) signed by proxy
        String device2SignedHeader = new MockClientAssertionHeader((RSAPrivateKey) proxyKeyPair.getPrivate())
                .mockSignedHeader(this.currentTimeSecs, DEVICE_1_ID, TENANT_ID);
        String proxyPublicKey = new String(TestKeyProvider.getPEMPublicKey(proxyKeyPair.getPublic()), UTF8);

        // setup test key provider
        this.tokenAuthenticator.setClientPublicKeyProvider(new MockKeyProvider());

        // provision client id d2 in mock
        when(this.clientDetailsService.loadClientByClientId(DEVICE_2_ID))
        .thenReturn(new BaseClientDetails(DEVICE_2_ID, null, null, null, null, null));
        
        //jwt assertion (sub: d2) , signed by d1
        String device1token = new MockAssertionToken().mockAssertionToken(DEVICE_1_CLIENT_ID, DEVICE_2_ID,
                System.currentTimeMillis(), 600, TENANT_ID, AUDIENCE);

        Assertions.assertThrows(AuthenticationException.class, () -> {
            this.tokenAuthenticator.authenticate(device1token, device2SignedHeader, proxyPublicKey);
        });

    }
    
}