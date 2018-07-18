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
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Collections.EMPTY_LIST;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;
import static org.cloudfoundry.identity.uaa.util.TokenValidation.validateAccessToken;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertFalse;
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
    private final SignatureVerifier verifier = new MacSigner("secret");

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

    @Before
    public void setup() {
        String defaultKeyId = "some-key-id";

        IdentityZone uaaZone = IdentityZone.getUaa();
        uaaZone.getConfig().getTokenPolicy().setKeys(
            map(entry(defaultKeyId, "foobar"))
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

        signer = new MacSigner("secret");

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
        String token = getToken();

        TokenValidation validation = TokenValidation.validateAccessToken(token);

        assertThat(validation.getValidationErrors(), not(empty()));
        assertThat(validation.getValidationErrors(), hasSize(1));
        assertThat(validation.getValidationErrors().get(0).getMessage(),
            equalTo("kid claim not found in JWT token header"));
    }

    @Test
    public void validate_KeyId_actuallyExists() {
        String kid = "garbage";
        header.put("kid", kid);

        String token = getToken();

        TokenValidation validation = TokenValidation.validateAccessToken(token);

        assertThat(validation.getValidationErrors(), not(empty()));
        assertThat(validation.getValidationErrors(), hasSize(1));
        assertThat(validation.getValidationErrors().get(0).getMessage(),
            equalTo("Token header claim [kid] references unknown signing key : [garbage]"));
    }

    @Test
    public void testGetClientById() {
        String token = getToken();

        ClientDetails clientDetails = TokenValidation.validateAccessToken(token)
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

        TokenValidation.validateAccessToken(token).getClientDetails(clientDetailsService);
    }

    @Test
    public void testGetUserById() {
        String token = getToken();

        UaaUser user = TokenValidation.validateAccessToken(token).getUserDetails(userDb);

        assertThat(user, notNullValue());
        assertThat(user.getUsername(), equalTo("marissa"));
        assertThat(user.getEmail(), equalTo("marissa@test.org"));
    }

    @Test
    public void testGetUserById_notUserToken() {
        content.put("grant_type", "client_credentials");
        String token = getToken();

        UaaUser user = TokenValidation.validateAccessToken(token).getUserDetails(userDb);

        assertThat(user, nullValue());
    }

    @Test
    public void testGetUserById_invalidUserId() {
        String invalidUserId = "invalid-user-id";
        content.put(ClaimConstants.USER_ID, invalidUserId);
        String token = getToken();

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Token bears a non-existent user ID: " + invalidUserId);

        UaaUser user = TokenValidation.validateAccessToken(token).getUserDetails(userDb);
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
        TokenValidation validation = spy(validateAccessToken(getToken()));

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
        validation.checkClientAndUser(uaaClient, uaaUser);
        verify(validation, times(1))
            .checkRequiredUserGroups((Collection<String>) argThat(containsInAnyOrder(new String[] {"group1", "group2"})),
                                     (Collection<String>) argThat(containsInAnyOrder(uaaUserGroups.toArray(new String[0])))
            );

    }

    @Test
    public void required_groups_are_present() throws Exception {
        TokenValidation validation = validateAccessToken(getToken());
        uaaClient.addAdditionalInformation(REQUIRED_USER_GROUPS, uaaUserGroups);
        assertTrue(validation.checkClientAndUser(uaaClient, uaaUser).throwIfInvalid().isValid());
    }


    @Test
    public void required_groups_are_missing() throws Exception {
        TokenValidation validation = validateAccessToken(getToken());
        uaaUserGroups.add("group-missing-from-user");
        uaaClient.addAdditionalInformation(REQUIRED_USER_GROUPS, uaaUserGroups);
        assertFalse(validation.checkClientAndUser(uaaClient, uaaUser).isValid());

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("User does not meet the client's required group criteria.");
        validation.throwIfInvalid();

    }

    @Test
    public void validateToken() throws Exception {

        TokenValidation validation = validateAccessToken(getToken())
                .checkSignature(verifier)
                .checkIssuer("http://localhost:8080/uaa/oauth/token")
                .checkClient((clientId) -> clientDetailsService.loadClientByClientId(clientId))
                .checkExpiry(oneSecondBeforeTheTokenExpires)
                .checkUser((uid) -> userDb.retrieveUserById(uid))
                .checkScopesInclude("acme.dev")
                .checkScopesWithin("acme.dev", "another.scope")
                .checkRevocationSignature(Collections.singletonList("fa1c787d"))
                .checkAudience("acme", "app")
                .checkRevocableTokenStore(revocableTokenProvisioning)
                .checkAccessToken()
                ;

        assertThat(validation.getValidationErrors(), empty());
        assertTrue(validation.isValid());
    }

    @Test
    public void testValidateAccessToken() throws Exception {
        content.put(JTI, "8b14f193-8212-4af2-9927-e3ae903f94a6-r");

        TokenValidation validation = validateAccessToken(getToken())
          .checkAccessToken();

        assertThat(validation.getValidationErrors(), not(empty()));
        assertThat(validation.getValidationErrors(), hasSize(1));
        assertThat(validation.getValidationErrors().get(0), instanceOf(InvalidTokenException.class));
        assertThat(validation.getValidationErrors().get(0).getMessage(), is("Invalid access token."));

        assertThat(validation.isValid(), is(false));
    }

    @Test
    public void validateAccessToken_with_dashR_in_JTI_should_fail_validation() throws Exception {
        content.put(JTI, "8b14f193-r-8212-4af2-9927-e3ae903f94a6");

        TokenValidation validation = validateAccessToken(getToken())
          .checkAccessToken();

        assertThat(validation.getValidationErrors(), empty());
        assertThat(validation.isValid(), is(true));
    }

    @Test
    public void validateAccessToken_without_jti_should_fail_validation() throws Exception {
        content.put(JTI, null);

        TokenValidation validation = validateAccessToken(getToken())
          .checkAccessToken();

        assertThat(validation.getValidationErrors(), hasSize(1));
        assertThat(validation.getValidationErrors().get(0), instanceOf(InvalidTokenException.class));
        assertThat(validation.getValidationErrors().get(0).getMessage(), is("The token must contain a jti claim."));

        assertThat(validation.isValid(), is(false));
    }

    @Test
    public void validateToken_Without_Email_And_Username() throws Exception {
        TokenValidation validation = validateAccessToken(getToken(Arrays.asList(EMAIL, USER_NAME)))
            .checkSignature(verifier)
            .checkIssuer("http://localhost:8080/uaa/oauth/token")
            .checkClient((clientId) -> clientDetailsService.loadClientByClientId(clientId))
            .checkExpiry(oneSecondBeforeTheTokenExpires)
            .checkUser((uid) -> userDb.retrieveUserById(uid))
            .checkScopesInclude("acme.dev")
            .checkScopesWithin("acme.dev", "another.scope")
            .checkRevocationSignature(Collections.singletonList("fa1c787d"))
            .checkAudience("acme", "app")
            .checkRevocableTokenStore(revocableTokenProvisioning)
            ;

        assertThat(validation.getValidationErrors(), empty());
        assertTrue(validation.isValid());
    }

    @Test
    public void tokenSignedWithDifferentKey() throws Exception {
        signer = new MacSigner("some_other_key");

        TokenValidation validation = validateAccessToken(getToken())
                .checkSignature(verifier);
        // opaque tokens should remain valid even through a signing key being removed
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void invalidJwt() throws Exception {
        TokenValidation validation = validateAccessToken("invalid.jwt.token");
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void tokenWithInvalidIssuer() throws Exception {
        TokenValidation validation = validateAccessToken(getToken())
                .checkIssuer("http://wrong.issuer/");
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void emptyBodyJwt() throws Exception {
        content = null;
        TokenValidation validation = validateAccessToken(getToken());
        assertThat(validation.getValidationErrors(), empty());
        assertTrue("Token with no claims is valid after decoding.", validation.isValid());

        assertFalse("Token with no claims fails issuer check.", validation.clone().checkIssuer("http://localhost:8080/uaa/oauth/token").isValid());
        assertFalse("Token with no claims fails expiry check.", validation.clone().checkExpiry(oneSecondBeforeTheTokenExpires).isValid());
    }

    @Test
    public void expiredToken() {
        TokenValidation validation = validateAccessToken(getToken())
                .checkExpiry(oneSecondAfterTheTokenExpires);
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void nonExistentUser() {
        UaaUserDatabase userDb = new InMemoryUaaUserDatabase(Collections.emptySet());

        TokenValidation validation = validateAccessToken(getToken())
            .checkUser((uid) -> userDb.retrieveUserById(uid));
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void userHadScopeRevoked() {
        UaaUserDatabase userDb = new MockUaaUserDatabase(u -> u
                .withUsername("marissa")
                .withId("a7f07bf6-e720-4652-8999-e980189cef54")
                .withEmail("marissa@test.org")
                .withAuthorities(Collections.singletonList(new SimpleGrantedAuthority("a.different.scope"))));

        TokenValidation validation = validateAccessToken(getToken())
            .checkUser((uid) -> userDb.retrieveUserById(uid));
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void tokenHasInsufficientScope() {
        TokenValidation validation = validateAccessToken(getToken())
                .checkScopesInclude("a.different.scope");
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InsufficientScopeException.class)));
    }

    @Test
    public void tokenContainsRevokedScope() {
        TokenValidation validation = validateAccessToken(getToken())
                .checkScopesWithin("a.different.scope");
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void nonExistentClient() {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.setClientDetailsStore(Collections.emptyMap());
        TokenValidation validation = validateAccessToken(getToken())
            .checkClient((clientId) -> clientDetailsService.loadClientByClientId(clientId));
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void clientHasScopeRevoked() {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.setClientDetailsStore(Collections.singletonMap("app", new BaseClientDetails("app", "acme", "a.different.scope", "authorization_code", "")));

        TokenValidation validation = validateAccessToken(getToken())
            .checkClient((clientId) -> clientDetailsService.loadClientByClientId(clientId));
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void clientRevocationHashChanged() {
        TokenValidation validation = validateAccessToken(getToken()).checkRevocationSignature(Collections.singletonList("New-Hash"));
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void clientRevocationHashChanged_and_Should_Pass() {
        TokenValidation validation = validateAccessToken(getToken()).checkRevocationSignature(Arrays.asList("fa1c787d", "New-Hash"));
        assertTrue(validation.isValid());

        validation = validateAccessToken(getToken()).checkRevocationSignature(Arrays.asList("New-Hash", "fa1c787d"));
        assertTrue(validation.isValid());

    }

    @Test
    public void incorrectAudience() {
        TokenValidation validation = validateAccessToken(getToken())
                .checkAudience("app", "somethingelse");
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void emptyAudience() {
        TokenValidation validation = validateAccessToken(getToken())
            .checkAudience("");
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void tokenIsRevoked() {
        RevocableTokenProvisioning revocableTokenProvisioning = mock(RevocableTokenProvisioning.class);
        when(revocableTokenProvisioning.retrieve("8b14f193-8212-4af2-9927-e3ae903f94a6", IdentityZoneHolder.get().getId()))
            .thenThrow(new EmptyResultDataAccessException(1));

        TokenValidation validation = validateAccessToken(getToken())
            .checkRevocableTokenStore(revocableTokenProvisioning);

        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void nonRevocableToken() {
        revocableTokenProvisioning = mock(RevocableTokenProvisioning.class);
        when(revocableTokenProvisioning.retrieve("8b14f193-8212-4af2-9927-e3ae903f94a6", IdentityZoneHolder.get().getId()))
            .thenThrow(new EmptyResultDataAccessException(1)); // should not occur

        content.remove("revocable");

        TokenValidation validation = validateAccessToken(getToken())
            .checkRevocableTokenStore(revocableTokenProvisioning);

        verifyZeroInteractions(revocableTokenProvisioning);
        assertThat(validation.getValidationErrors(), empty());
        assertTrue(validation.isValid());
    }
}
