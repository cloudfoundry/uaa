package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;

public class JwtHelperTest {
    private KeyInfo keyInfo;

    @Before
    public void setUp() {
        keyInfo = KeyInfoBuilder.build("testKid", "symmetricKey", "http://localhost/uaa");
    }

    @Test
    public void testKidInHeader() {
        Jwt jwt = JwtHelper.encode("testJwtContent", keyInfo);
        assertEquals("testKid", jwt.getHeader().getKid());

        jwt = JwtHelper.decode(jwt.getEncoded());
        assertEquals("testKid", jwt.getHeader().getKid());
    }

    @Test
    public void jwtHeaderShouldContainJkuInTheHeader() {
        Jwt jwt = JwtHelper.encode("testJwtContent", keyInfo);
        assertThat(jwt.getHeader().getJku(), is("https://localhost/uaa/token_keys"));
    }
}