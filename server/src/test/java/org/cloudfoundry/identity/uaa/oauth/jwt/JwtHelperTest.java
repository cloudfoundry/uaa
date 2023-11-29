package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.util.Arrays;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

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
        Jwt jwt = JwtHelper.encode(JsonUtils.writeValueAsString(Map.of("sub", "testJwtContent")), keyInfo);
        assertEquals("testKid", jwt.getHeader().getKid());

        jwt = JwtHelper.decode(jwt.getEncoded());
        assertEquals("testKid", jwt.getHeader().getKid());
    }

    @Test
    public void jwtHeaderShouldContainJkuInTheHeader() {
        Jwt jwt = JwtHelper.encode(JsonUtils.writeValueAsString(Map.of("sub", "testJwtContent")), keyInfo);
        assertEquals("https://localhost/uaa/token_keys", jwt.getHeader().getJku());
    }

    @Test
    public void jwtHeaderShouldNotContainJkuInTheHeaderIfCertificateDefined() {
        KeyInfo rsaKeyInfo = KeyInfoBuilder.build("key-id-1", privatekey, "http://localhost/uaa", "RS256", certificate);
        Jwt jwt = JwtHelper.encodePlusX5t(JsonUtils.writeValueAsString(Map.of("sub", "testJwtContent")), rsaKeyInfo, rsaKeyInfo.verifierCertificate().orElse(null));
        assertNull(jwt.getHeader().getJku());
        assertEquals("RkckJulawIoaTm0iaziJBwFh7Nc", jwt.getHeader().getX5t());
    }

    @Test
    public void testAudClaimTypes() {
        Jwt audSingle = JwtHelper.encode(JsonUtils.writeValueAsString(Map.of("sub", "subject", "aud", "single")), keyInfo);
        Jwt audArray = JwtHelper.encode(JsonUtils.writeValueAsString(Map.of("sub", "subject", "aud", Arrays.asList("one"))), keyInfo);
        Jwt audArrayThree = JwtHelper.encode(JsonUtils.writeValueAsString(Map.of("sub", "subject", "aud", Arrays.asList("one", "two", "three"))), keyInfo);

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
}
