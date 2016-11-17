package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class JwtHelperTest {

    @Test
    public void testKidInHeader() {
        Signer signer = new CommonSigner("testKid", "symmetricKey");
        Jwt jwt = JwtHelper.encode("testJwtContent", signer);
        assertEquals("testKid", jwt.getHeader().getKid());

        jwt = JwtHelper.decode(jwt.getEncoded());
        assertEquals("testKid", jwt.getHeader().getKid());
    }

}