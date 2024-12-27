/*
 * *****************************************************************************
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
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.cloudfoundry.identity.uaa.client.InMemoryClientDetailsService;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.jwt.ChainedSignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.SignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.UaaMacSigner;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.MockUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.InMemoryMultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANTED_SCOPES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SCOPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA.buildAccessTokenValidator;
import static org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA.buildIdTokenValidator;
import static org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA.buildRefreshTokenValidator;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.DEFAULT_UAA_URL;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.hamcrest.MockitoHamcrest.argThat;

public class JwtTokenSignedByThisUAATest {
    public static final String CLIENT_ID = "app";
    public static final String USER_ID = "a7f07bf6-e720-4652-8999-e980189cef54";
    private final SignatureVerifier verifier = new KeyInfo("some-key-id", macSigningKeySecret, DEFAULT_UAA_URL, "HS256", null).getVerifier();

    private final Instant oneSecondAfterTheTokenExpires = Instant.ofEpochSecond(1458997132 + 1);
    private final Instant oneSecondBeforeTheTokenExpires = Instant.ofEpochSecond(1458997132 - 1);
    private Map<String, Object> header;
    private Map<String, Object> content;
    private JWSSigner signer;
    private RevocableTokenProvisioning revocableTokenProvisioning;
    private InMemoryMultitenantClientServices inMemoryMultitenantClientServices;
    private UaaUserDatabase userDb;
    private UaaUser uaaUser;
    private UaaClientDetails uaaClient;
    private Collection<String> uaaUserGroups;

    private List<String> logEvents;
    private AbstractAppender appender;

    public JwtTokenSignedByThisUAATest() throws ParseException {
    }

    @Before
    public void setupLogger() {
        logEvents = new ArrayList<>();
        appender = new AbstractAppender("", null, null) {
            @Override
            public void append(LogEvent event) {
                logEvents.add("%s -- %s".formatted(event.getLevel().name(), event.getMessage().getFormattedMessage()));
            }
        };
        appender.start();

        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        context.getRootLogger().addAppender(appender);
    }

    @After
    public void resetStdout() {
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        context.getRootLogger().removeAppender(appender);
    }

    @BeforeClass
    public static void beforeClass() {
        TestUtils.resetIdentityZoneHolder(null);
    }

    @AfterClass
    public static void afterClass() {
        TestUtils.resetIdentityZoneHolder(null);
    }

    @Rule
    public ExpectedException expectedException = ExpectedException.none();
    private static final String macSigningKeySecret = "foobarfoobarfoobarfoobarfoobarfoofoobarfoobarfoobarfoobarfoobarfoobar";

    @Before
    public void setup() throws KeyLengthException {
        String defaultKeyId = "some-key-id";

        IdentityZone uaaZone = IdentityZone.getUaa();
        uaaZone.getConfig().getTokenPolicy().setKeys(
                map(entry(defaultKeyId, macSigningKeySecret))
        );
        IdentityZoneProvisioning identityZoneProvisioning = mock(IdentityZoneProvisioning.class);
        when(identityZoneProvisioning.retrieve(anyString())).thenReturn(uaaZone);

        IdentityZoneHolder.setProvisioning(identityZoneProvisioning);
        IdentityZoneHolder.set(uaaZone);

        header = map(
                entry("alg", "HS256"),
                entry("kid", defaultKeyId)
        );

        content = map(
                entry("jti", "8b14f193-8212-4af2-9927-e3ae903f94a6"),
                entry("nonce", "04e2e934200b4b9fbe5d4e70ae18ba8e"),
                entry("sub", "a7f07bf6-e720-4652-8999-e980189cef54"),
                entry("scope", Collections.singletonList("acme.dev")),
                entry("client_id", "app"),
                entry("cid", "app"),
                entry("azp", "app"),
                entry("grant_type", GRANT_TYPE_AUTHORIZATION_CODE),
                entry("user_id", "a7f07bf6-e720-4652-8999-e980189cef54"),
                entry("origin", "uaa"),
                entry("user_name", "marissa"),
                entry("email", "marissa@test.org"),
                entry("auth_time", 1458953554),
                entry("rev_sig", "fa1c787d"),
                entry("iat", Instant.now().minusSeconds(30).toEpochMilli()),
                entry("exp", Instant.now().plusSeconds(600).toEpochMilli()),
                entry("iss", "http://localhost:8080/uaa/oauth/token"),
                entry("zid", "uaa"),
                entry("aud", Arrays.asList("app", "acme")),
                entry("revocable", true)
        );

        signer = new UaaMacSigner(new SecretKeySpec(macSigningKeySecret.getBytes(StandardCharsets.UTF_8), "HS256"));

        IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());

        inMemoryMultitenantClientServices = new InMemoryMultitenantClientServices(mockIdentityZoneManager);
        uaaClient = new UaaClientDetails("app", "acme", "acme.dev", GRANT_TYPE_AUTHORIZATION_CODE, "");
        uaaClient.addAdditionalInformation(REQUIRED_USER_GROUPS, Collections.emptyList());
        inMemoryMultitenantClientServices.setClientDetailsStore(IdentityZone.getUaaZoneId(),
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
        uaaUserGroups = uaaUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    }

    @Test
    public void validate_KeyId_isPresent() {
        header = map(entry("alg", "HS256"));

        expectedException.expectMessage("kid claim not found in JWT token header");

        assertThat(buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost")), notNullValue());
    }

    @Test
    public void validate_KeyId_actuallyExists() {
        String kid = "garbage";
        header.put("kid", kid);

        expectedException.expectMessage("Token header claim [kid] references unknown signing key : [garbage]");

        JwtTokenSignedByThisUAA.buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"));
    }

    @Test
    public void validation_succeeds_with_different_alg() {
        header.put("alg", "HS512");
        JwtTokenSignedByThisUAA jwtTokenSignedByThisUAA = buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkIssuer("http://localhost:8080/uaa/oauth/token")
                .checkSignature();
        assertThat(jwtTokenSignedByThisUAA, notNullValue());
        assertThat(jwtTokenSignedByThisUAA.toString(), notNullValue());
        assertThat(jwtTokenSignedByThisUAA.getJwt().toString(), notNullValue());
        assertThat(jwtTokenSignedByThisUAA.getJwt().getHeader().toString(), notNullValue());
        assertThat(jwtTokenSignedByThisUAA.getJwt().getEncoded(), notNullValue());
        assertThat(jwtTokenSignedByThisUAA.getJwt().getHeader().getAlg(), containsString("HS512"));
    }

    @Test
    public void validation_with_rs256_rs384_and_rs512_algorithm() {
        IdentityZone uaaZone = IdentityZone.getUaa();
        uaaZone.getConfig().getTokenPolicy().setKeys(
                map(entry("0", """
                        -----BEGIN RSA PRIVATE KEY-----
                        MIIEpAIBAAKCAQEAqL/ATjXzKjxPgYdR9dD436dPRhpa247RD/NroC5/KA19QksN
                        3v5rIjVJUdBQ4iT1qKKzHtuqgpaxr7ofw8566O4tLb6Xv5RyYO7NoQup2t+/m17/
                        G8zej6jmugZK+aDXuTuAXyiWcNCesNPtUiAdVQnLMNHW95CsgS9X7M9GQ4guu3sU
                        vEPd+HCapacx/rGiv9a7NQnNP8xO5c54RReIuFjLGAoyYHpzjGk+/wtuepRbC1cP
                        xYSn7yi1Mkh4iqBV63EhBmHhAEGkwpGZ50kDSKDsJEbiHFy0gwxKNIYAGV0+zmUw
                        oLhQ/t1l4VTqEPr0LEmdI2kRA2AwWZqqUF5XcQIDAQABAoIBAQChJeTGi5y4k7m1
                        T33EiphwNL1ui9KCY2NgoSwBXwXNQPyCZ1xKvJmgpFRtTcs/+t2h+iWl7U5qwO/U
                        iaC2A6O6d2ErkxwlNuT3jnVOOu4s94lqHZDvgnhzpm8X7NSCiMgZuym/Nepct80j
                        vm6fA84fHGgvKeToq/8gqw6DNfm6mHArHQ1wl6S5vc87fr/sxHmdGJSfDPJJdsAZ
                        AulfPKSq05+KlbnRoDAtT4ECRg/hcZ0OSS8Po0F1Yn+7QBMn7/3JB7xAZa8o7APy
                        d+HI72Q1TZVpSprHZFaVjbzY5OVt4y9zNQH9O3e4l46S9KTgCiWZBVkIhXf7BYUW
                        gVHx/C7xAoGBANYQGFZnIgBNc3Z30x2iga8v1UgVeCR/o2utf+lIkVSpVCGxK4+1
                        OyjzmThCaBWBIjLa1W/4XxMAXd6BF/kdW1HKD221Vu0bFB96sfCXX3e4z7yYuuOR
                        6/nofneTbFUSmnMVcaTqjrQFwDLUhwKoJeQ1VjPMCwn1ITePpA3kl0ntAoGBAMnP
                        B2TB7OCHl5Ns5iIMdorpEvp3EbzRDqIC3HZgs/vh/U9I2U7avLefE4zJFcGmlG/Y
                        nkSkgcvS5lrC2DVGfNCek1Upj+j7yf4eU+sylDwDIJ1wdbzp8HYKTrjYPYtBwkVV
                        aaw0fFN637UKwQ1vfMFh8MXfIHj9GdWVGdcRhYMVAoGABJenzgK8agE/XuVHNDWO
                        TrHaA4fiYfYTDXZVbi3OYGCZm3dvlc+vizteqCRUk1GH6EtllNdhQskZOnLOjtug
                        X+rT1ei0CrYwAlThiGXW+HyQiF1GdSdmRqBERlB1XIXfpmRpYb5efWI6M1z34Ii2
                        92RliwrvmbEWm1iLjni+/ikCgYBy1WdzohXUPdO2hAT/4u+hY7b05sQlGSCmd9JT
                        WfuQnKuzbdSZ1kYEhnRtbA8BPnTAoBaPILzq6ntBshWtWwqy+0kC8L9+56es/jzq
                        XMGU1IK+k7urX8MAqCTbcdCzaRvOsCeNYeBM8GJTdmcb6hCnSb/kGG816W/F5S3q
                        /4FlcQKBgQC187xHduIFArF3XihiSA4zLgrLBfdvbP4fPYlzKflTnPKtlzqlrDpL
                        iJ5TA2qTZ7wn7dOl4epgc11plQZa9yA4d6b8abdJLhuEu+vF3XfwYibqM4axikRc
                        81tiTbWzc/xTVjLvFZTZCDAe7e4WjthF/E7GE4AxgfFXWXDP+rN/NQ==
                        -----END RSA PRIVATE KEY-----"""))
        );
        IdentityZoneHolder.set(uaaZone);
        IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        // alg: RS256
        buildAccessTokenValidator(
                "eyJhbGciOiJSUzI1NiIsImtpZCI6IjAiLCJ0eXAiOiJKV1QifQ."
                        + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImpvaG4iLCJhZG1pbiI6dHJ1ZX0."
                        + "EFjWTH-T1xJJBS6FOi83M6wuV_9R8tgJ-Y6MfPf55yTQ90qhuUu0VbHktbI1ual0V_DQ8m3gzyF7au3WAO6FwwMJFvkNOrenCuZk00XrPjx_IDa2ewCJQ7mpLH9t8wS"
                        + "mZtHethtGWLDeXdGn1YfP4awcHnMxW33sHE22RjXAH_LrNW5b2scCrzR3UrSa32aMrCSy19goL7SR813Q92Gd-KXPohkstsDSVGg7qwwWh9NsjRYcRYHylqJO3TYCWL"
                        + "Fa0bMQ49pG7lQsSH-rOqPduw7olwmRBt2waA9o-YsbWSeIZGkJ11kZPzMf0IkPWRsx8P5C0ZoOuBqKUynY2ljwaA",
                new KeyInfoService("https://localhost")).checkSignature();
        // alg: RS384
        buildAccessTokenValidator(
                "eyJhbGciOiJSUzM4NCIsImtpZCI6IjAiLCJ0eXAiOiJKV1QifQ."
                        + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImpvaG4iLCJhZG1pbiI6dHJ1ZX0."
                        + "Olf3eDtbAZtbzXDz-K07quiRf2ml2T98ywmBgHMPSSh8hIex_Qya8mDuSbra4z-PaxRXy1eGsk2dC2EguBjy5_mzpPetcyd6t-XyNK3msml2Cgs0vET5bPC4J5X2ohw"
                        + "UqzlUAZwe7_h0wH3pk2IHYTlB0xelI2Wajw_NoTMBkwgdYICB7VchlO8Pn-3_04qZu5JFQ5aUp-0Pb05jxxGk7RqLiohrGbKKscaN8P4Rq5fw-Gn81ry0Ge_rKVzTaN"
                        + "-vpmCnYKMzIqtdsUXTWWnswE0hTKqKVW0DkUU8-sO11jKYZTma-HUaWcmi5Chg73-R_9so_VCHxN_Jj4FUmfdLWA",
                new KeyInfoService("https://localhost")).checkSignature();
        // alg: RS512
        buildAccessTokenValidator(
                "eyJhbGciOiJSUzUxMiIsImtpZCI6IjAiLCJ0eXAiOiJKV1QifQ."
                        + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImpvaG4iLCJhZG1pbiI6dHJ1ZX0."
                        + "guEkBUbMJ_b4YULBAE0Cw6dgNNUh03C3rhno3oFjjFwfgze8JUgKpwiKxBu2URZCoeA-pfdj4Mp0I8hz4x6W9C_FubFs0ihnxGWc053EVowgohvGZAoBRZ4S_Rkydhz"
                        + "-16abJ_7tgoieR5g_1t5hSIX7EsKJF0V2Pxyn2OdsGZqe2cPbrxfzgIuH52k4oA3CXljXzBE7stc2Rbs6SlBijpXqc2mqfQWmG0QUy_iO2LqTAHFmgwHgJQONK5RVMba"
                        + "JVM6yhYgiz8LmHy3gSHjI-kDBYDjVDPmpX_oI6jf-nfXd0q-lhKvpqjyKzBHWMbHFIJTJTVSFuDlJZpjosY_A8w",
                new KeyInfoService("https://localhost")).checkSignature();
    }

    @Test
    public void testGetClientById() {
        String token = getToken();


        ClientDetails clientDetails = JwtTokenSignedByThisUAA.buildAccessTokenValidator(token, new KeyInfoService("https://localhost"))
                .getClientDetails(inMemoryMultitenantClientServices);

        assertThat(clientDetails.getClientId(), equalTo(content.get("cid")));
    }

    @Test
    public void testGetClientById_invalidId() {
        String invalidClientId = "invalid-client-id";
        content.put("cid", invalidClientId);
        String token = getToken();

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Invalid client ID " + invalidClientId);

        JwtTokenSignedByThisUAA.buildAccessTokenValidator(token, new KeyInfoService("https://localhost")).getClientDetails(inMemoryMultitenantClientServices);
    }

    @Test
    public void testGetUserById() {
        String token = getToken();

        UaaUser user = JwtTokenSignedByThisUAA.buildAccessTokenValidator(token, new KeyInfoService("https://localhost")).getUserDetails(userDb);

        assertThat(user, notNullValue());
        assertThat(user.getUsername(), equalTo("marissa"));
        assertThat(user.getEmail(), equalTo("marissa@test.org"));
    }

    @Test
    public void testGetUserById_notUserToken() {
        content.put("grant_type", "client_credentials");
        String token = getToken();

        UaaUser user = JwtTokenSignedByThisUAA.buildAccessTokenValidator(token, new KeyInfoService("https://localhost")).getUserDetails(userDb);

        assertThat(user, nullValue());
    }

    @Test
    public void testGetUserById_invalidUserId() {
        String invalidUserId = "invalid-user-id";
        content.put(ClaimConstants.USER_ID, invalidUserId);
        String token = getToken();

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Token bears a non-existent user ID: " + invalidUserId);

        JwtTokenSignedByThisUAA.buildAccessTokenValidator(token, new KeyInfoService("https://localhost")).getUserDetails(userDb);
    }

    private String getToken() {
        return getToken(emptyList());
    }

    private String getToken(Collection<String> excludedClaims) {
        Map<String, Object> content = this.content != null ? new HashMap(this.content) : null;
        for (String key : excludedClaims) {
            content.remove(key);
        }
        return UaaTokenUtils.constructToken(header, content, signer);
    }

    @Test
    public void validate_required_groups_is_invoked() {
        JwtTokenSignedByThisUAA jwtToken = spy(buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost")));

        jwtToken.checkClientAndUser(uaaClient, uaaUser);
        verify(jwtToken, times(1))
                .checkRequiredUserGroups((Collection<String>) argThat(containsInAnyOrder(new String[0])),
                        (Collection<String>) argThat(containsInAnyOrder(uaaUserGroups.toArray(new String[0])))
                );
        Mockito.reset(jwtToken);

        uaaClient.addAdditionalInformation(REQUIRED_USER_GROUPS, null);
        jwtToken.checkClientAndUser(uaaClient, uaaUser);
        verify(jwtToken, times(1))
                .checkRequiredUserGroups((Collection<String>) argThat(containsInAnyOrder(new String[0])),
                        (Collection<String>) argThat(containsInAnyOrder(uaaUserGroups.toArray(new String[0])))
                );

        uaaClient.addAdditionalInformation(REQUIRED_USER_GROUPS, Arrays.asList("group1", "group2"));
        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList("group1,group2");

        authorities.addAll(AuthorityUtils.createAuthorityList(uaaUserGroups.toArray(new String[0])));
        uaaUser = uaaUser.authorities(authorities);

        jwtToken.checkClientAndUser(uaaClient, uaaUser);
        verify(jwtToken, times(1))
                .checkRequiredUserGroups((Collection<String>) argThat(containsInAnyOrder(new String[]{"group1", "group2"})),
                        (Collection<String>) argThat(containsInAnyOrder(uaaUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).toArray()))
                );
    }

    @Test
    public void required_groups_are_present() {
        JwtTokenSignedByThisUAA jwtToken = buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"));
        uaaClient.addAdditionalInformation(REQUIRED_USER_GROUPS, uaaUserGroups);

        jwtToken.checkClientAndUser(uaaClient, uaaUser);
    }

    @Test
    public void required_groups_are_missing() {
        JwtTokenSignedByThisUAA jwtToken = buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"));
        uaaUserGroups.add("group-missing-from-user");
        uaaClient.addAdditionalInformation(REQUIRED_USER_GROUPS, uaaUserGroups);

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("User does not meet the client's required group criteria.");

        jwtToken.checkClientAndUser(uaaClient, uaaUser);
    }

    @Test
    public void checking_token_happy_case() {
        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkIssuer("http://localhost:8080/uaa/oauth/token")
                .checkClient(clientId -> inMemoryMultitenantClientServices.loadClientByClientId(clientId))
                .checkExpiry(oneSecondBeforeTheTokenExpires)
                .checkUser(uid -> userDb.retrieveUserById(uid))
                .checkRequestedScopesAreGranted("acme.dev", "another.scope")
                .checkRevocationSignature(Collections.singletonList("fa1c787d"))
                .checkAudience("acme", "app")
                .checkRevocableTokenStore(revocableTokenProvisioning)
                .checkJti();
    }

    @Test
    public void checkJti_givenRefreshToken() {
        content.put(JTI, "8b14f193-8212-4af2-9927-e3ae903f94a6-r");

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Invalid access token.");

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost")).checkJti();
    }

    @Test
    public void checkJti_with_dashR_in_JTI_should_not_fail_validation() {
        String dashR = "-r";
        content.put(JTI, "8b14f193" + dashR + "-8212-4af2-9927-e3ae903f94a6");

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkJti();
    }

    @Test
    public void checkJti_without_jti_should_fail_validation() {
        content.put(JTI, null);

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("The token must contain a jti claim.");

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkJti();
    }

    @Test
    public void validateToken_Without_Email_And_Username_should_not_throw_exception() {
        buildAccessTokenValidator(
                getToken(Arrays.asList(EMAIL, USER_NAME)), new KeyInfoService("https://localhost"))
                .checkSignature(verifier)
                .checkIssuer("http://localhost:8080/uaa/oauth/token")
                .checkClient(clientId -> inMemoryMultitenantClientServices.loadClientByClientId(clientId))
                .checkExpiry(oneSecondBeforeTheTokenExpires)
                .checkUser(uid -> userDb.retrieveUserById(uid))
                .checkRequestedScopesAreGranted("acme.dev", "another.scope")
                .checkRevocationSignature(Collections.singletonList("fa1c787d"))
                .checkAudience("acme", "app")
                .checkRevocableTokenStore(revocableTokenProvisioning);
    }

    @Test
    public void buildIdTokenValidator_performsSignatureValidation() {
        ChainedSignatureVerifier signatureVerifier = mock(ChainedSignatureVerifier.class);
        when(signatureVerifier.getDelegates()).thenReturn(Arrays.asList(verifier));
        buildIdTokenValidator(getToken(), signatureVerifier, new KeyInfoService("https://localhost"));

        verify(signatureVerifier).getDelegates();
    }

    @Test
    public void idTokenValidator_rejectsTokensWithRefreshTokenSuffix() {
        expectedException.expect(InvalidTokenException.class);

        content.put(JTI, "asdfsafsa-r");
        buildIdTokenValidator(getToken(), mock(ChainedSignatureVerifier.class), new KeyInfoService("https://localhost")).checkJti();
    }

    @Test
    public void idTokenValidator_findsScopesFromScopeClaim() {
        content.put(SCOPE, Lists.newArrayList("openid"));
        content.put(GRANTED_SCOPES, Lists.newArrayList("foo.read"));
        ChainedSignatureVerifier validator = mock(ChainedSignatureVerifier.class);
        when(validator.getDelegates()).thenReturn(Arrays.asList(verifier));

        List<String> scopes = buildIdTokenValidator(getToken(), validator, new KeyInfoService("https://localhost")).requestedScopes();
        assertThat(scopes, equalTo(Lists.newArrayList("openid")));
    }

    @Test
    public void tokenSignedWithDifferentKey() throws KeyLengthException {
        signer = new UaaMacSigner(new SecretKeySpec("some_other_key".getBytes(), "HS256"));

        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkSignature(verifier);
    }

    @Test
    public void invalidJwt() {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator("invalid.jwt.token", new KeyInfoService("https://localhost"));
    }

    @Test
    public void tokenWithInvalidIssuer() {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost")).checkIssuer("http://wrong.issuer/");
    }

    @Test
    public void emptyBodyJwt_failsCheckingIssuer() {
        content.remove("iss");
        JwtTokenSignedByThisUAA jwtToken = buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"));

        expectedException.expect(InvalidTokenException.class);
        jwtToken.checkIssuer("http://localhost:8080/uaa/oauth/token");
    }

    @Test
    public void emptyBodyJwt_failsCheckingExpiry() {
        content.remove("exp");
        JwtTokenSignedByThisUAA jwtToken = buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"));

        expectedException.expect(InvalidTokenException.class);
        jwtToken.checkExpiry(oneSecondBeforeTheTokenExpires);
    }

    @Test
    public void expiredToken() {
        content.put("iat", 1458997132);
        content.put("exp", 1458997132);
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkExpiry(oneSecondAfterTheTokenExpires);
    }

    @Test
    public void nonExistentUser() {
        UaaUserDatabase userDb = new InMemoryUaaUserDatabase(Collections.emptySet());
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkUser(userDb::retrieveUserById);

    }

    @Test
    public void userHadScopeRevoked() {
        UaaUserDatabase userDb = new MockUaaUserDatabase(u -> u
                .withUsername("marissa")
                .withId("a7f07bf6-e720-4652-8999-e980189cef54")
                .withEmail("marissa@test.org")
                .withAuthorities(Collections.singletonList(new SimpleGrantedAuthority("a.different.scope"))));

        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkUser(userDb::retrieveUserById);
    }

    @Test
    public void tokenHasInsufficientScope() {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkRequestedScopesAreGranted("a.different.scope");
    }

    @Test
    public void tokenContainsRevokedScope() {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkRequestedScopesAreGranted("a.different.scope");
    }

    @Test
    public void nonExistentClient() {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.setClientDetailsStore(Collections.emptyMap());

        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkClient(clientDetailsService::loadClientByClientId);
    }

    @Test
    public void clientHasScopeRevoked() {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.setClientDetailsStore(
                Collections.singletonMap(
                        "app",
                        new UaaClientDetails("app", "acme", "a.different.scope", GRANT_TYPE_AUTHORIZATION_CODE, "")
                )
        );

        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkClient(clientDetailsService::loadClientByClientId);
    }

    @Test
    public void clientRevocationHashChanged() {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkRevocationSignature(Collections.singletonList("New-Hash"));
    }

    @Test
    public void clientRevocationHashChanged_and_Should_Pass() {
        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkRevocationSignature(Arrays.asList("fa1c787d", "New-Hash"));

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkRevocationSignature(Arrays.asList("New-Hash", "fa1c787d"));
    }

    @Test
    public void incorrectAudience() {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkAudience("app", "somethingelse");
    }

    @Test
    public void emptyAudience() {
        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkAudience("");
    }

    @Test
    public void tokenIsRevoked() {
        RevocableTokenProvisioning revocableTokenProvisioning = mock(RevocableTokenProvisioning.class);
        when(revocableTokenProvisioning.retrieve(
                "8b14f193-8212-4af2-9927-e3ae903f94a6",
                IdentityZoneHolder.get().getId()
        )).thenThrow(new EmptyResultDataAccessException(1));

        expectedException.expect(InvalidTokenException.class);

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkRevocableTokenStore(revocableTokenProvisioning);
    }

    @Test
    public void nonRevocableToken() {
        revocableTokenProvisioning = mock(RevocableTokenProvisioning.class);
        when(revocableTokenProvisioning.retrieve("8b14f193-8212-4af2-9927-e3ae903f94a6", IdentityZoneHolder.get().getId()))
                .thenThrow(new EmptyResultDataAccessException(1)); // should not occur

        content.remove("revocable");

        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkRevocableTokenStore(revocableTokenProvisioning);

        verifyNoInteractions(revocableTokenProvisioning);
    }

    @Test
    public void validateRefreshToken_happycase() {
        // Build a refresh token
        content.remove(SCOPE);
        content.put(JTI, content.get(JTI) + "-r");
        content.put(GRANTED_SCOPES, Collections.singletonList("some-granted-scope"));

        String refreshToken = getToken();

        buildRefreshTokenValidator(refreshToken, new KeyInfoService("https://localhost"))
                .checkRequestedScopesAreGranted("some-granted-scope");
    }

    @Test
    public void checkRequestedScopesAreGranted_withScopeClaimAndNotGrantedScopeClaim_happycase() {
        // Build a refresh token
        content.put(JTI, content.get(JTI) + "-r");
        content.put(SCOPE, Collections.singletonList("some-granted-scope"));
        content.remove(GRANTED_SCOPES);

        String refreshToken = getToken();

        buildRefreshTokenValidator(refreshToken, new KeyInfoService("https://localhost"))
                .checkRequestedScopesAreGranted("some-granted-scope");
    }

    @Test
    public void checkRequestedScopesAreGranted_withScopeClaimAndGrantedScopeClaim_happycase() {
        // Build a refresh token
        content.put(JTI, content.get(JTI) + "-r");
        content.put(SCOPE, Collections.singletonList("another-granted-scope"));
        content.put(GRANTED_SCOPES, Collections.singletonList("some-granted-scope"));

        String refreshToken = getToken();

        buildRefreshTokenValidator(refreshToken, new KeyInfoService("https://localhost"))
                .checkRequestedScopesAreGranted("some-granted-scope");

        assertThat(logEvents, not(hasItems(containsString("ERROR"))));
        assertThat(logEvents, not(hasItems(containsString("error"))));
    }

    @Test
    public void checkRequestedScopesAreGranted_should_fail_when_missing_scopes() {
        // Build a refresh token
        content.put(JTI, content.get(JTI) + "-r");
        content.put(GRANTED_SCOPES, Arrays.asList("some-granted-scope", "bruce", "josh"));

        String refreshToken = getToken();

        expectedException.expectMessage(
                "Some required \"granted_scopes\" are missing: [some-granted-scope, bruce, josh]"
        );

        buildRefreshTokenValidator(refreshToken, new KeyInfoService("https://localhost"))
                .checkRequestedScopesAreGranted((Collection) content.get(SCOPE));
    }

    @Test
    public void checkRequestedScopesAreGranted_ignoresGrantedScopesClaim() {
        List<String> grantedScopes = Collections.singletonList("some-granted-scope");
        content.put(GRANTED_SCOPES, grantedScopes);
        content.remove(SCOPE);
        String refreshToken = getToken();

        String expectedErrorMessage = "The token does not bear a \"scope\" claim.";
        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage(expectedErrorMessage);

        JwtTokenSignedByThisUAA jwtToken = buildAccessTokenValidator(
                refreshToken,
                new KeyInfoService("https://localhost")
        );

        try {
            jwtToken.checkRequestedScopesAreGranted(grantedScopes);
        } catch (InvalidTokenException e) {
            assertThat(logEvents, hasItem("ERROR -- " + expectedErrorMessage));
            throw e; // rethrow so that expectedException can see the exception
        }
    }

    @Test
    public void getScopes_rejects_invalid_scope_claim() {
        content.put(SCOPE, "i am not a list!!!");
        String refreshToken = getToken();

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("The token's \"scope\" claim is invalid or unparseable.");

        buildAccessTokenValidator(refreshToken, new KeyInfoService("https://localhost"))
                .requestedScopes();
    }

    @Test
    public void readScopesFromClaim_rejects_non_string_scopes() {
        content.put(SCOPE, Arrays.asList("hello", 1L));
        String refreshToken = getToken();

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("The token's \"scope\" claim is invalid or unparseable.");

        buildAccessTokenValidator(refreshToken, new KeyInfoService("https://localhost"))
                .requestedScopes();
    }

    @Test(expected = InvalidTokenException.class)
    public void nullUserIsCaught() {
        buildAccessTokenValidator(getToken(), new KeyInfoService("https://localhost"))
                .checkUser(uid -> null);
    }
}
