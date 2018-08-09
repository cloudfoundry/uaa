package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;

public class JwtHelperTest {
    private Signer signer;

    @Before
    public void setUp() {
        signer = new CommonSigner("testKid", "symmetricKey", "http://localhost/uaa");
    }

    @Test
    public void testKidInHeader() {
        Jwt jwt = JwtHelper.encode("testJwtContent", signer);
        assertEquals("testKid", jwt.getHeader().getKid());

        jwt = JwtHelper.decode(jwt.getEncoded());
        assertEquals("testKid", jwt.getHeader().getKid());
    }

    @Test
    public void jwtHeaderShouldContainJkuInTheHeader() {
        Jwt jwt = JwtHelper.encode("testJwtContent", signer);
        assertThat(jwt.getHeader().getJku(), is("http://localhost/uaa"));
    }
}