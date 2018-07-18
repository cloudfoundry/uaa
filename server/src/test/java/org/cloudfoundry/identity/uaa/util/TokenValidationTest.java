/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.util;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.MockUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.InMemoryClientServicesExtentions;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Collections.EMPTY_LIST;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANTED_SCOPES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SCOPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;
import static org.cloudfoundry.identity.uaa.util.TokenValidation.buildAccessTokenValidator;
import static org.cloudfoundry.identity.uaa.util.TokenValidation.buildRefreshTokenValidator;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.hamcrest.MockitoHamcrest.argThat;

public class TokenValidationTest {
    public static final String CLIENT_ID = "app";
    public static final String USER_ID = "a7f07bf6-e720-4652-8999-e980189cef54";
    private final SignatureVerifier verifier = new MacSigner("foobar");

    private final Instant oneSecondAfterTheTokenExpires = Instant.ofEpochSecond(1458997132 + 1);
    private final Instant oneSecondBeforeTheTokenExpires = Instant.ofEpochSecond(1458997132 - 1);
    private Map<String, Object> header;
    private Map<String, Object> content;
    private Signer signer;
    private RevocableTokenProvisioning revocableTokenProvisioning;
    private InMemoryClientServicesExtentions clientDetailsService;
    private UaaUserDatabase userDb;
    private UaaUser uaaUser;
    private BaseClientDetails uaaClient;
    private Collection<String> uaaUserGroups;
    private IdentityZoneProvisioning identityZoneProvisioning;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();
    private static final String macSigningKeySecret = "foobar";

    @Before
    public void setup() {
        String defaultKeyId = "some-key-id";

        IdentityZone uaaZone = IdentityZone.getUaa();
        uaaZone.getConfig().getTokenPolicy().setKeys(
          map(entry(defaultKeyId, macSigningKeySecret))
        );
        identityZoneProvisioning = mock(IdentityZoneProvisioning.class);
        when(identityZoneProvisioning.retrieve(anyString())).thenReturn(uaaZone);

        IdentityZoneHolder.setProvisioning(identityZoneProvisioning);

        header = map(
          entry("alg", "HS256"),
          entry("kid", defaultKeyId)
        );

        content = map(
          entry("jti", "8b14f193-8212-4af2-9927-e3ae903f94a6"),
          entry("nonce", "04e2e934200b4b9fbe5d4e70ae18ba8e"),
          entry("sub", "a7f07bf6-e720-4652-8999-e980189cef54"),
          entry("scope", Arrays.asList("acme.dev")),
          entry("client_id", "app"),
          entry("cid", "app"),
          entry("azp", "app"),
          entry("grant_type", "authorization_code"),
          entry("user_id", "a7f07bf6-e720-4652-8999-e980189cef54"),
          entry("origin", "uaa"),
          entry("user_name", "marissa"),
          entry("email", "marissa@test.org"),
          entry("auth_time", 1458953554),
          entry("rev_sig", "fa1c787d"),
          entry("iat", 1458953932),
          entry("exp", 1458997132),
          entry("iss", "http://localhost:8080/uaa/oauth/token"),
          entry("zid", "uaa"),
          entry("aud", Arrays.asList("app", "acme")),
          entry("revocable", true)
        );

        signer = new MacSigner(macSigningKeySecret);

        clientDetailsService = new InMemoryClientServicesExtentions();
        uaaClient = new BaseClientDetails("app", "acme", "acme.dev", "authorization_code", "");
        uaaClient.addAdditionalInformation(REQUIRED_USER_GROUPS, Arrays.asList());
        clientDetailsService.setClientDetailsStore(IdentityZone.getUaa().getId(),
          Collections.singletonMap(CLIENT_ID, uaaClient));
        revocableTokenProvisioning = mock(RevocableTokenProvisioning.class);

        when(revocableTokenProvisioning.retrieve("8b14f193-8212-4af2-9927-e3ae903f94a6", IdentityZoneHolder.get().getId()))
          .thenReturn(new RevocableToken().setValue(UaaTokenUtils.constructToken(header, content, signer)));

        userDb = new MockUaaUserDatabase(u -> u
          .withUsername("marissa")
          .withId(USER_ID)
          .withEmail("marissa@test.org")
          .withAuthorities(Collections.singletonList(new SimpleGrantedAuthority("acme.dev"))));

        uaaUser = userDb.retrieveUserById(USER_ID);
        uaaUserGroups = uaaUser.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.toList());

    }

    @Test
    public void validate_KeyId_isPresent() {
        header = map(entry("alg", "HS256"));

        expectedException.expectMessage("kid claim not found in JWT token header");

        TokenValidation.buildAccessTokenValidator(getToken());
    }

    @Test
    public void validate_KeyId_actuallyExists() {
        String kid = "garbage";
        header.put("kid", kid);

        expectedException.expectMessage("Token header claim [kid] references unknown signing key : [garbage]");

        TokenValidation.buildAccessTokenValidator(getToken());
    }

    @Test
    public void testGetClientById() {
        String token = getToken();

        ClientDetails clientDetails = TokenValidation.buildAccessTokenValidator(token)
          .getClientDetails(clientDetailsService);

        assertThat(clientDetails.getClientId(), equalTo(content.get("cid")));
    }

    @Test
    public void testGetClientById_invalidId() {
        String invalidClientId = "invalid-client-id";
        content.put("cid", invalidClientId);
        String token = getToken();

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Invalid client ID " + invalidClientId);

        TokenValidation.buildAccessTokenValidator(token).getClientDetails(clientDetailsService);
    }

    @Test
    public void testGetUserById() {
        String token = getToken();

        UaaUser user = TokenValidation.buildAccessTokenValidator(token).getUserDetails(userDb);

        assertThat(user, notNullValue());
        assertThat(user.getUsername(), equalTo("marissa"));
        assertThat(user.getEmail(), equalTo("marissa@test.org"));
    }

    @Test
    public void testGetUserById_notUserToken() {
        content.put("grant_type", "client_credentials");
        String token = getToken();

        UaaUser user = TokenValidation.buildAccessTokenValidator(token).getUserDetails(userDb);

        assertThat(user, nullValue());
    }

    @Test
    public void testGetUserById_invalidUserId() {
        String invalidUserId = "invalid-user-id";
        content.put(ClaimConstants.USER_ID, invalidUserId);
        String token = getToken();

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Token bears a non-existent user ID: " + invalidUserId);

        UaaUser user = TokenValidation.buildAccessTokenValidator(token).getUserDetails(userDb);
    }

    private String getToken() {
        return getToken(EMPTY_LIST);
    }

    private String getToken(Collection<String> excludedClaims) {
        Map<String, Object> content = this.content != null ? new HashMap(this.content) : null;
        for (String key : excludedClaims) {
            content.remove(key);
        }
        return UaaTokenUtils.constructToken(header, content, signer);
    }

    @Test
    public void validate_required_groups_is_invoked() throws Exception {
        TokenValidation validation = spy(buildAccessTokenValidator(getToken()));

        validation.checkClientAndUser(uaaClient, uaaUser);
        verify(validation, times(1))
          .checkRequiredUserGroups((Collection<String>) argThat(containsInAnyOrder(new String[0])),
            (Collection<String>) argThat(containsInAnyOrder(uaaUserGroups.toArray(new String[0])))
          );
        Mockito.reset(validation);

        uaaClient.addAdditionalInformation(REQUIRED_USER_GROUPS, null);
        validation.checkClientAndUser(uaaClient, uaaUser);
        verify(validation, times(1))
          .checkRequiredUserGroups((Collection<String>) argThat(containsInAnyOrder(new String[0])),
            (Collection<String>) argThat(containsInAnyOrder(uaaUserGroups.toArray(new String[0])))
          );

        uaaClient.addAdditionalInformation(REQUIRED_USER_GROUPS, Arrays.asList("group1", "group2"));
        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList("group1,group2");

        authorities.addAll(AuthorityUtils.createAuthorityList(uaaUserGroups.toArray(new String[uaaUserGroups.size()])));
        uaaUser = uaaUser.authorities(authorities);

        validation.checkClientAndUser(uaaClient, uaaUser);
        verify(validation, times(1))
          .checkRequiredUserGroups((Collection<String>) argThat(containsInAnyOrder(new String[]{"group1", "group2"})),
            (Collection<String>) argThat(containsInAnyOrder(uaaUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).toArray()))
          );
    }

    @Test
    public void required_groups_are_present() throws Exception {
        TokenValidation validation = buildAccessTokenValidator(getToken());
        uaaClient.addAdditionalInformation(REQUIRED_USER_GROUPS, uaaUserGroups);

        validation.checkClientAndUser(uaaClient, uaaUser);
    }


    @Test
    public void required_groups_are_missing() throws Exception {
        TokenValidation validation = buildAccessTokenValidator(getToken());
        uaaUserGroups.add("group-missing-from-user");
        uaaClient.addAdditionalInformation(REQUIRED_USER_GROUPS, uaaUserGroups);

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("User does not meet the client's required group criteria.");

        validation.checkClientAndUser(uaaClient, uaaUser);
    }

    @Test
    public void testValidateAccessToken() throws Exception {
        buildAccessTokenValidator(getToken())
          .checkIssuer("http://localhost:8080/uaa/oauth/token")
          .checkClient((clientId) -> clientDetailsService.loadClientByClientId(clientId))
          .checkExpiry(oneSecondBeforeTheTokenExpires)
          .checkUser((uid) -> userDb.retrieveUserById(uid))
          .checkScopesWithin("acme.dev", "another.scope")
          .checkRevocationSignature(Collections.singletonList("fa1c787d"))
          .checkAudience("acme", "app")
          .checkRevocableTokenStore(revocableTokenProvisioning)
          .checkAccessToken();

        assertTrue(true);
    }

    @Test
    public void testValidateAccessToken_givenRefreshToken() throws Exception {
        content.put(JTI, "8b14f193-8212-4af2-9927-e3ae903f94a6-r");

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Invalid access token.");

        buildAccessTokenValidator(getToken())
          .checkAccessToken();
    }

    @Test
    public void validateAccessToken_with_dashR_in_JTI_should_not_fail_validation() throws Exception {
        String dashR = "-r";
        content.put(JTI, "8b14f193" + dashR + "-8212-4af2-9927-e3ae903f94a6");

        buildAccessTokenValidator(getToken())
          .checkAccessToken();
    }

    @Test
    public void validateAccessToken_without_jti_should_fail_validation() throws Exception {
        content.put(JTI, null);

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("The token must contain a jti claim.");

        buildAccessTokenValidator(getToken())
          .checkAccessToken();
    }

    @Test
    public void validateToken_Without_Email_And_Username_should_not_throw_exception() throws Exception {
        buildAccessTokenValidator(
          getToken(Arrays.asList(EMAIL, USER_NAME)))
          .checkSignature(verifier)
          .checkIssuer("http://localhost:8080/uaa/oauth/token")
          .checkClient((clientId) -> clientDetailsService.loadClientByClientId(clientId))
          .checkExpiry(oneSecondBeforeTheTokenExpires)
          .checkUser((uid) -> userDb.retrieveUserById(uid))
          .checkScopesWithin("acme.dev", "another.scope")
          .checkRevocationSignature(Collections.singletonList("fa1c787d"))
          .checkAudience("acme", "app")
          .checkRevocableTokenStore(revocableTokenProvisioning);
    }

    @Test
    public void tokenSignedWithDifferentKey() throws Exception {
        signer = new MacSigner("some_other_key");

        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken())
          .checkSignature(verifier);
    }

    @Test
    public void invalidJwt() throws Exception {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator("invalid.jwt.token");
    }

    @Test
    public void tokenWithInvalidIssuer() throws Exception {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken()).checkIssuer("http://wrong.issuer/");
    }

    @Test
    public void emptyBodyJwt_failsCheckingIssuer() throws Exception {
        content = null;
        TokenValidation validation = buildAccessTokenValidator(getToken());

        expectedException.expect(InvalidTokenException.class);
        validation.checkIssuer("http://localhost:8080/uaa/oauth/token");
    }

    @Test
    public void emptyBodyJwt_failsCheckingExpiry() throws Exception {
        content = null;
        TokenValidation validation = buildAccessTokenValidator(getToken());

        expectedException.expect(InvalidTokenException.class);
        validation.checkExpiry(oneSecondBeforeTheTokenExpires);
    }

    @Test
    public void expiredToken() {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken())
          .checkExpiry(oneSecondAfterTheTokenExpires);
    }

    @Test
    public void nonExistentUser() {
        UaaUserDatabase userDb = new InMemoryUaaUserDatabase(Collections.emptySet());
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken())
          .checkUser(userDb::retrieveUserById);

    }

    @Test
    public void userHadScopeRevoked() {
        UaaUserDatabase userDb = new MockUaaUserDatabase(u -> u
          .withUsername("marissa")
          .withId("a7f07bf6-e720-4652-8999-e980189cef54")
          .withEmail("marissa@test.org")
          .withAuthorities(Collections.singletonList(new SimpleGrantedAuthority("a.different.scope"))));

        expectedException.expect(InsufficientScopeException.class);

        buildAccessTokenValidator(getToken())
          .checkUser(userDb::retrieveUserById);
    }

    @Test
    public void tokenHasInsufficientScope() {
        expectedException.expect(InsufficientScopeException.class);

        buildAccessTokenValidator(getToken())
          .checkScopesWithin("a.different.scope");
    }

    @Test
    public void tokenHasIntegerScope() {
        this.content.put(SCOPE, Lists.newArrayList("a.different.scope", 1, "another.different.scope", null));

        buildAccessTokenValidator(getToken())
          .checkScopesWithin("a.different.scope", "1", "another.different.scope");
    }

    @Test
    public void tokenContainsRevokedScope() {
        expectedException.expect(InsufficientScopeException.class);

        buildAccessTokenValidator(getToken())
          .checkScopesWithin("a.different.scope");
    }

    @Test
    public void nonExistentClient() {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.setClientDetailsStore(Collections.emptyMap());

        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken())
          .checkClient(clientDetailsService::loadClientByClientId);
    }

    @Test
    public void clientHasScopeRevoked() {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.setClientDetailsStore(
          Collections.singletonMap(
            "app",
            new BaseClientDetails("app", "acme", "a.different.scope", "authorization_code", "")
          )
        );

        expectedException.expect(InsufficientScopeException.class);

        buildAccessTokenValidator(getToken())
          .checkClient(clientDetailsService::loadClientByClientId);
    }

    @Test
    public void clientRevocationHashChanged() {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken())
          .checkRevocationSignature(Collections.singletonList("New-Hash"));
    }

    @Test
    public void clientRevocationHashChanged_and_Should_Pass() {
        buildAccessTokenValidator(getToken())
          .checkRevocationSignature(Arrays.asList("fa1c787d", "New-Hash"));

        buildAccessTokenValidator(getToken())
          .checkRevocationSignature(Arrays.asList("New-Hash", "fa1c787d"));
    }

    @Test
    public void incorrectAudience() {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken())
          .checkAudience("app", "somethingelse");
    }

    @Test
    public void emptyAudience() {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken())
          .checkAudience("");
    }

    @Test
    public void tokenIsRevoked() {
        RevocableTokenProvisioning revocableTokenProvisioning = mock(RevocableTokenProvisioning.class);
        when(revocableTokenProvisioning.retrieve(
          "8b14f193-8212-4af2-9927-e3ae903f94a6",
          IdentityZoneHolder.get().getId()
          )
        ).thenThrow(new EmptyResultDataAccessException(1));

        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken())
          .checkRevocableTokenStore(revocableTokenProvisioning);
    }

    @Test
    public void nonRevocableToken() {
        revocableTokenProvisioning = mock(RevocableTokenProvisioning.class);
        when(revocableTokenProvisioning.retrieve("8b14f193-8212-4af2-9927-e3ae903f94a6", IdentityZoneHolder.get().getId()))
          .thenThrow(new EmptyResultDataAccessException(1)); // should not occur

        content.remove("revocable");

        buildAccessTokenValidator(getToken())
          .checkRevocableTokenStore(revocableTokenProvisioning);

        verifyZeroInteractions(revocableTokenProvisioning);
    }

    @Test
    public void validateRefreshToken() {
        // Build a refresh token
        content.put(JTI, content.get(JTI) + "-r");
        content.put(GRANTED_SCOPES, Collections.singletonList("some-granted-scope"));

        String refreshToken = getToken();
        buildRefreshTokenValidator(refreshToken)
          .checkScopesWithin("some-granted-scope");

        expectedException.expectMessage("Some required granted_scopes are missing: some-granted-scope");

        buildRefreshTokenValidator(refreshToken)
            .checkScopesWithin((Collection) content.get(SCOPE));
    }

    @Test
    public void validateRefreshToken_ignoresScopesClaim() {
        String accessToken = getToken();

        expectedException.expectMessage("The token does not bear a granted_scopes claim.");

        buildRefreshTokenValidator(accessToken)
            .checkScopesWithin((Collection) content.get(SCOPE));
    }

    @Test
    public void validateAccessToken_ignoresGrantedScopesClaim() {
        content.put(GRANTED_SCOPES, Collections.singletonList("some-granted-scope"));
        content.remove(SCOPE);
        String refreshToken = getToken();

        expectedException.expectMessage("The token does not bear a scope claim.");

        buildAccessTokenValidator(refreshToken)
            .checkScopesWithin((Collection) content.get(GRANTED_SCOPES));
    }
}
