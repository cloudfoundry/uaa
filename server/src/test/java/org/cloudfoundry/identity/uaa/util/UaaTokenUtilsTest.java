package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptySet;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.util.UaaTokenUtils.hasRequiredUserAuthorities;
import static org.cloudfoundry.identity.uaa.util.UaaTokenUtils.isUserToken;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;

public class UaaTokenUtilsTest {

    @Test
    public void testRevocationHash() {
        List<String> salts = new LinkedList<>();
        for (int i=0; i<3; i++) {
            salts.add(new RandomValueStringGenerator().generate());
        }
        String hash1 = UaaTokenUtils.getRevocationHash(salts);
        String hash2 = UaaTokenUtils.getRevocationHash(salts);
        assertFalse("Hash 1 should not be empty",StringUtils.isEmpty(hash1));
        assertFalse("Hash 2 should not be empty", StringUtils.isEmpty(hash2));
        assertEquals(hash1, hash2);
    }

    @Test
    public void isJwtToken() {

        RandomValueStringGenerator generator = new RandomValueStringGenerator(36);
        String regular = generator.generate();
        String jwt = generator.generate() + "." + generator.generate() + "." + generator.generate();
        assertFalse(UaaTokenUtils.isJwtToken(regular));
        assertTrue(UaaTokenUtils.isJwtToken(jwt));
    }

    @Test
    public void is_user_token() {
        Map<String, Object> claims = new HashMap();

        //no grant type - always is a user token
        assertTrue(isUserToken(claims));
        for (String grantType : Arrays.asList(GRANT_TYPE_PASSWORD, GRANT_TYPE_IMPLICIT, GRANT_TYPE_AUTHORIZATION_CODE)) {
            claims.put(GRANT_TYPE, grantType);
            assertTrue(isUserToken(claims));
        }

        claims.put(GRANT_TYPE, "client_credentials");
        assertFalse(isUserToken(claims));

        claims.clear();

        //user_id present - must be user token
        claims.put(ClaimConstants.USER_ID, "id");
        assertTrue(isUserToken(claims));

        //no user id and no grant type present - client token if sub.equals(cid)
        claims.clear();
        claims.put(SUB, "someClientId");
        claims.put(CID, "someClientId");
        assertFalse(isUserToken(claims));
   }

    @Test
    public void required_user_groups_null_args_are_ok() {
        assertTrue(hasRequiredUserAuthorities(null, null));
        assertTrue(hasRequiredUserAuthorities(emptySet(), null));
        assertTrue(hasRequiredUserAuthorities(null, emptySet()));
        assertTrue(hasRequiredUserAuthorities(emptySet(), emptySet()));
    }

    @Test
    public void test_required_user_authorities_invalid() {
        List<String> requiredGroups = Arrays.asList("scope1","scope2","scope3","scope4");
        List<GrantedAuthority> userGroups = Arrays.asList(
            new SimpleGrantedAuthority("scope1"),
            new SimpleGrantedAuthority("scope2"),
            new SimpleGrantedAuthority("scope3"),
            new SimpleGrantedAuthority("scope5")
        );

        assertFalse(UaaTokenUtils.hasRequiredUserAuthorities(requiredGroups, userGroups));
    }

    @Test
    public void test_required_user_authorities_valid() {
        List<String> requiredGroups = Arrays.asList("scope1","scope2","scope3");
        List<GrantedAuthority> userGroups = Arrays.asList(
            new SimpleGrantedAuthority("scope1"),
            new SimpleGrantedAuthority("scope2"),
            new SimpleGrantedAuthority("scope3"),
            new SimpleGrantedAuthority("scope4")
        );
        assertTrue(UaaTokenUtils.hasRequiredUserAuthorities(requiredGroups, userGroups));
    }


    @Test
    public void test_required_user_groups_invalid() {
        List<String> requiredGroups = Arrays.asList("scope1","scope2","scope3", "scope5");
        List<String> userGroups = Arrays.asList("scope1","scope2","scope3","scope4");
        assertFalse(UaaTokenUtils.hasRequiredUserGroups(requiredGroups, userGroups));
    }

    @Test
    public void test_required_user_groups_valid() {
        List<String> requiredGroups = Arrays.asList("scope1","scope2","scope3");
        List<String> userGroups = Arrays.asList("scope1","scope2","scope3","scope4");
        assertTrue(UaaTokenUtils.hasRequiredUserGroups(requiredGroups, userGroups));
    }
    
    @Test
    public void getClaims() {
        Map<String, Object> headers = new HashMap<>();
        headers.put("kid", "some-key");
        headers.put("alg", "HS256");
        Map<String, Object> content = new HashMap<>();
        content.put("cid", "openidclient");
        content.put("origin", "uaa");
        String jwt = UaaTokenUtils.constructToken(headers, content, new MacSigner("foobar"));

        Map<String, Object> claims = UaaTokenUtils.getClaims(jwt);

        assertEquals(claims.get("cid"), "openidclient");
        assertEquals(claims.get("origin"), "uaa");
    }

    @Test(expected = InvalidTokenException.class)
    public void getClaims_throwsExceptionWhenJwtIsMalformed() {
        UaaTokenUtils.getClaims("not.a.jwt");
    }

    @Test(expected = InvalidTokenException.class)
    public void getClaims_throwsExceptionWhenClaimsCannotBeRead() {
        Jwt encoded = JwtHelper.encode("great content", KeyInfoBuilder.build("foo", "bar", "https://localhost/uaa"));
        UaaTokenUtils.getClaims(encoded.getEncoded());
    }

    @Test
    public void getClaims_WhenClaimsAreMissing_returnsEmptyMap() {
        Map<String, Object> headers = new HashMap<>();
        headers.put("kid", "some-key");
        headers.put("alg", "HS256");
        String tokenWithNoClaims = UaaTokenUtils.constructToken(headers, null, new MacSigner("foobar"));

        Map<String, Object> claims = UaaTokenUtils.getClaims(tokenWithNoClaims);

        assertNotNull(claims);
        assertEquals(claims.size(), 0);
    }

}