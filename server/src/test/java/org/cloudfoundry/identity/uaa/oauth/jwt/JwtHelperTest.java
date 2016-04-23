package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.junit.Test;
import org.springframework.security.jwt.crypto.sign.MacSigner;

import static org.junit.Assert.*;

public class JwtHelperTest {

    @Test
    public void testKidInHeader() {
        Signer signer = new IdentifiedSigner("testKid", new MacSigner("symmetricKey"));
        Jwt jwt = JwtHelper.encode("testJwtContent", signer);
        assertEquals("testKid", jwt.getHeader().getKid());

        jwt = JwtHelper.decode(jwt.getEncoded());
        assertEquals("testKid", jwt.getHeader().getKid());
    }

}