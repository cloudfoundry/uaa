package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.jwk.JWKParameterNames;
import org.cloudfoundry.identity.uaa.oauth.InvalidSignatureException;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.DEFAULT_UAA_URL;

class JwtHelperTest {
    private KeyInfo keyInfo;

    private static final String certificate = getResourceAsString(JwtHelperTest.class, "certificate.pem");
    private static final String privatekey = getResourceAsString(JwtHelperTest.class, "privatekey.pem");

    @BeforeEach
    void setUp() {
        keyInfo = KeyInfoBuilder.build("testKid", "symmetricKey", "http://localhost/uaa");
    }

    @Test
    void kidInHeader() {
        Jwt jwt = JwtHelper.encode(Map.of("sub", "testJwtContent"), keyInfo);
        assertThat(jwt.getHeader().getKid()).isEqualTo("testKid");

        jwt = JwtHelper.decode(jwt.getEncoded());
        assertThat(jwt.getHeader().getKid()).isEqualTo("testKid");
    }

    @Test
    void jwtHeaderShouldContainJkuInTheHeader() {
        Jwt jwt = JwtHelper.encode(Map.of("sub", "testJwtContent"), keyInfo);
        assertThat(jwt.getHeader().getJku()).isEqualTo("https://localhost/uaa/token_keys");
    }

    @Test
    void jwtHeaderShouldNotContainJkuInTheHeaderIfCertificateDefined() {
        KeyInfo rsaKeyInfo = KeyInfoBuilder.build("key-id-1", privatekey, "http://localhost/uaa", "RS256", certificate);
        Jwt jwt = JwtHelper.encodePlusX5t(Map.of("sub", "testJwtContent"), rsaKeyInfo, rsaKeyInfo.verifierCertificate().orElse(null));
        assertThat(jwt.getHeader().getJku()).isNull();
        assertThat(jwt.getHeader().getX5t()).isEqualTo("RkckJulawIoaTm0iaziJBwFh7Nc");
    }

    @Test
    void audClaimTypes() {
        Jwt audSingle = JwtHelper.encode(Map.of("sub", "subject", "aud", "single"), keyInfo);
        Jwt audArray = JwtHelper.encode(Map.of("sub", "subject", "aud", Arrays.asList("one")), keyInfo);
        Jwt audArrayThree = JwtHelper.encode(Map.of("sub", "subject", "aud", Arrays.asList("one", "two", "three")), keyInfo);

        Claims claimSingle = UaaTokenUtils.getClaimsFromTokenString(audSingle.getEncoded());
        assertThat(claimSingle).isNotNull();
        assertThat(claimSingle.getAud()).isEqualTo(Arrays.asList("single"));

        Claims claimArray = UaaTokenUtils.getClaimsFromTokenString(audArray.getEncoded());
        assertThat(claimArray).isNotNull();
        assertThat(claimArray.getAud()).isEqualTo(Arrays.asList("one"));

        Claims claimArrayThree = UaaTokenUtils.getClaimsFromTokenString(audArrayThree.getEncoded());
        assertThat(claimArrayThree).isNotNull();
        assertThat(claimArrayThree.getAud()).isEqualTo(Arrays.asList("one", "two", "three"));
    }

    @Test
    void legacyHmacVerify() {
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
        assertThat(legacySignature).isNotNull();
        Jwt legacyVerify = JwtHelper.decode(legacySignature.getEncoded());
        assertThat(legacyVerify).isNotNull();
        legacyVerify.verifySignature(cs);
        assertThatExceptionOfType(InvalidSignatureException.class).isThrownBy(() -> legacyVerify.verifySignature(keyInfo.getVerifier()));
        key.put("value", "wrong");
        assertThatExceptionOfType(InvalidSignatureException.class).isThrownBy(() -> legacyVerify.verifySignature(new SignatureVerifier(new JsonWebKey(key))));
    }

    @Test
    void legacyHmacFailed() {
        assertThatExceptionOfType(InvalidSignatureException.class).isThrownBy(() -> UaaMacSigner.verify("x", null));
    }

    @Test
    void jwtInvalidPayload() {
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() -> JwtHelper.encode(null, keyInfo));
    }

    @Test
    void jwtInvalidContent() {
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() -> JwtHelper.decode("invalid"));
        assertThatExceptionOfType(InsufficientAuthenticationException.class).isThrownBy(() -> JwtHelper.decode(""));
    }
}
