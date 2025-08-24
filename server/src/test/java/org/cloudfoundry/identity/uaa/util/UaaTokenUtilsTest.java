package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.jwt.UaaMacSigner;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptySet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.util.UaaTokenUtils.hasRequiredUserAuthorities;
import static org.cloudfoundry.identity.uaa.util.UaaTokenUtils.isUserToken;

class UaaTokenUtilsTest {
    @Test
    void revocationHash() {
        List<String> salts = new LinkedList<>();
        for (int i = 0; i < 3; i++) {
            salts.add(new AlphanumericRandomValueStringGenerator().generate());
        }
        String hash1 = UaaTokenUtils.getRevocationHash(salts);
        String hash2 = UaaTokenUtils.getRevocationHash(salts);
        assertThat(hash1).isNotEmpty();
        assertThat(hash2).isNotEmpty()
                .isEqualTo(hash1);
    }

    @Test
    void isJwtToken() {
        AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator(36);
        String regular = generator.generate();
        String jwt = generator.generate() + "." + generator.generate() + "." + generator.generate();
        assertThat(UaaTokenUtils.isJwtToken(regular)).isFalse();
        assertThat(UaaTokenUtils.isJwtToken(jwt)).isTrue();
    }

    @Test
    void is_user_token() {
        Map<String, Object> claims = new HashMap<>();

        //no grant type - always is a user token
        assertThat(isUserToken(claims)).isTrue();
        for (String grantType : Arrays.asList(GRANT_TYPE_PASSWORD, GRANT_TYPE_IMPLICIT, GRANT_TYPE_AUTHORIZATION_CODE)) {
            claims.put(GRANT_TYPE, grantType);
            assertThat(isUserToken(claims)).isTrue();
        }

        claims.put(GRANT_TYPE, "client_credentials");
        assertThat(isUserToken(claims)).isFalse();

        claims.clear();
        //user_id present - must be user token
        claims.put(ClaimConstants.USER_ID, "id");
        assertThat(isUserToken(claims)).isTrue();

        //no user id and no grant type present - client token if sub.equals(cid)
        claims.clear();
        claims.put(SUB, "someClientId");
        claims.put(CID, "someClientId");
        assertThat(isUserToken(claims)).isFalse();
    }

    @Test
    void required_user_groups_null_args_are_ok() {
        assertThat(hasRequiredUserAuthorities(null, null)).isTrue();
        assertThat(hasRequiredUserAuthorities(emptySet(), null)).isTrue();
        assertThat(hasRequiredUserAuthorities(null, emptySet())).isTrue();
        assertThat(hasRequiredUserAuthorities(emptySet(), emptySet())).isTrue();
    }

    @Test
    void required_user_authorities_invalid() {
        List<String> requiredGroups = Arrays.asList("scope1", "scope2", "scope3", "scope4");
        List<GrantedAuthority> userGroups = Arrays.asList(
                new SimpleGrantedAuthority("scope1"),
                new SimpleGrantedAuthority("scope2"),
                new SimpleGrantedAuthority("scope3"),
                new SimpleGrantedAuthority("scope5")
        );

        assertThat(UaaTokenUtils.hasRequiredUserAuthorities(requiredGroups, userGroups)).isFalse();
    }

    @Test
    void required_user_authorities_valid() {
        List<String> requiredGroups = Arrays.asList("scope1", "scope2", "scope3");
        List<GrantedAuthority> userGroups = Arrays.asList(
                new SimpleGrantedAuthority("scope1"),
                new SimpleGrantedAuthority("scope2"),
                new SimpleGrantedAuthority("scope3"),
                new SimpleGrantedAuthority("scope4")
        );
        assertThat(UaaTokenUtils.hasRequiredUserAuthorities(requiredGroups, userGroups)).isTrue();
    }

    @Test
    void required_user_groups_invalid() {
        List<String> requiredGroups = Arrays.asList("scope1", "scope2", "scope3", "scope5");
        List<String> userGroups = Arrays.asList("scope1", "scope2", "scope3", "scope4");
        assertThat(UaaTokenUtils.hasRequiredUserGroups(requiredGroups, userGroups)).isFalse();
    }

    @Test
    void required_user_groups_valid() {
        List<String> requiredGroups = Arrays.asList("scope1", "scope2", "scope3");
        List<String> userGroups = Arrays.asList("scope1", "scope2", "scope3", "scope4");
        assertThat(UaaTokenUtils.hasRequiredUserGroups(requiredGroups, userGroups)).isTrue();
    }

    @Test
    void getClaims() {
        Map<String, Object> headers = new HashMap<>();
        headers.put("kid", "some-key");
        headers.put("alg", "HS256");
        Map<String, Object> content = new HashMap<>();
        content.put("cid", "openidclient");
        content.put("origin", "uaa");
        content.put("aud", "openidclient");
        String jwt = UaaTokenUtils.constructToken(headers, content, new UaaMacSigner("foobar"));

        Map<String, Object> claims = UaaTokenUtils.getClaims(jwt, Map.class);

        assertThat(claims)
                .containsEntry("cid", "openidclient")
                .containsEntry("origin", "uaa")
                .containsEntry("aud", List.of("openidclient"));

        Claims claimObject = UaaTokenUtils.getClaimsFromTokenString(jwt);

        assertThat(claimObject.getCid()).isEqualTo(claims.get("cid"));
        assertThat(claimObject.getOrigin()).isEqualTo(claims.get("origin"));
        assertThat(claimObject.getAud()).isEqualTo(claims.get("aud"));
    }

    @Test
    void getClaims_throwsExceptionWhenJwtIsMalformed() {
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                UaaTokenUtils.getClaims("not.a.jwt", Map.class));
    }

    @Test
    void getClaims_WhenClaimsAreMissing_returnsEmptyMap() {
        Map<String, Object> headers = new HashMap<>();
        headers.put("kid", "some-key");
        headers.put("alg", "HS256");
        String tokenWithNoClaims = UaaTokenUtils.constructToken(headers, new HashMap<>(), new UaaMacSigner("foobar"));

        Map<String, Object> claims = UaaTokenUtils.getClaims(tokenWithNoClaims, Map.class);
        assertThat(claims).isEmpty();
    }
}
