package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.jwk.JWKParameterNames;
import org.cloudfoundry.identity.uaa.oauth.InvalidSignatureException;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.DEFAULT_UAA_URL;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

public class JwtHelperTest {
    private KeyInfo keyInfo;

    private static final String certificate = getResourceAsString(JwtHelperTest.class, "certificate.pem");
    private static final String privatekey = getResourceAsString(JwtHelperTest.class, "privatekey.pem");

    @Before
    public void setUp() {
        keyInfo = KeyInfoBuilder.build("testKid", "symmetricKey", "http://localhost/uaa");
    }

    @Test
    public void testKidInHeader() {
        Jwt jwt = JwtHelper.encode(Map.of("sub", "testJwtContent"), keyInfo);
        assertEquals("testKid", jwt.getHeader().getKid());

        jwt = JwtHelper.decode(jwt.getEncoded());
        assertEquals("testKid", jwt.getHeader().getKid());
    }

    @Test
    public void jwtHeaderShouldContainJkuInTheHeader() {
        Jwt jwt = JwtHelper.encode(Map.of("sub", "testJwtContent"), keyInfo);
        assertEquals("https://localhost/uaa/token_keys", jwt.getHeader().getJku());
    }

    @Test
    public void jwtHeaderShouldNotContainJkuInTheHeaderIfCertificateDefined() {
        KeyInfo rsaKeyInfo = KeyInfoBuilder.build("key-id-1", privatekey, "http://localhost/uaa", "RS256", certificate);
        Jwt jwt = JwtHelper.encodePlusX5t(Map.of("sub", "testJwtContent"), rsaKeyInfo, rsaKeyInfo.verifierCertificate().orElse(null));
        assertNull(jwt.getHeader().getJku());
        assertEquals("RkckJulawIoaTm0iaziJBwFh7Nc", jwt.getHeader().getX5t());
    }

    @Test
    public void testAudClaimTypes() {
        Jwt audSingle = JwtHelper.encode(Map.of("sub", "subject", "aud", "single"), keyInfo);
        Jwt audArray = JwtHelper.encode(Map.of("sub", "subject", "aud", Arrays.asList("one")), keyInfo);
        Jwt audArrayThree = JwtHelper.encode(Map.of("sub", "subject", "aud", Arrays.asList("one", "two", "three")), keyInfo);

        Claims claimSingle = UaaTokenUtils.getClaimsFromTokenString(audSingle.getEncoded());
        assertNotNull(claimSingle);
        assertEquals(Arrays.asList("single"), claimSingle.getAud());

        Claims claimArray = UaaTokenUtils.getClaimsFromTokenString(audArray.getEncoded());
        assertNotNull(claimArray);
        assertEquals(Arrays.asList("one"), claimArray.getAud());

        Claims claimArrayThree = UaaTokenUtils.getClaimsFromTokenString(audArrayThree.getEncoded());
        assertNotNull(claimArrayThree);
        assertEquals(Arrays.asList("one", "two", "three"), claimArrayThree.getAud());
    }

    @Test
    public void testLegacyHmacVerify() {
        String kid = "legacy-token-key";
        String keyValue = "tokenKey";
        HashMap key = new HashMap();
        key.put(JWKParameterNames.KEY_TYPE, "MAC");
        key.put(JWKParameterNames.KEY_ID, kid);
        key.put("value", keyValue);
        JsonWebKey jsonWebKey = new JsonWebKey(key);
        SignatureVerifier cs = new SignatureVerifier(jsonWebKey);
        KeyInfo hmacKeyInfo = new KeyInfo(kid, keyValue, DEFAULT_UAA_URL);
        Jwt legacySignature = JwtHelper.encode(Map.of("sub", "subject", "aud", "single"), hmacKeyInfo);
        assertNotNull(legacySignature);
        Jwt legacyVerify = JwtHelper.decode(legacySignature.getEncoded());
        assertNotNull(legacyVerify);
        legacyVerify.verifySignature(cs);
        assertThrows(InvalidSignatureException.class, () -> legacyVerify.verifySignature(keyInfo.getVerifier()));
        key.put("value", "wrong");
        assertThrows(InvalidSignatureException.class, () -> legacyVerify.verifySignature(new SignatureVerifier(new JsonWebKey(key))));
    }

    @Test
    public void testLegacyHmacFailed() {
        assertThrows(InvalidSignatureException.class, () -> UaaMacSigner.verify("x", null));
    }

    @Test
    public void testJwtInvalidPayload() {
        assertThrows(InvalidTokenException.class, () -> JwtHelper.encode(null, keyInfo));
    }

    @Test
    public void testJwtInvalidContent() {
        assertThrows(InvalidTokenException.class, () -> JwtHelper.decode("invalid"));
        assertThrows(InsufficientAuthenticationException.class, () -> JwtHelper.decode(""));
    }
}
