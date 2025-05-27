/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.Sets;
import org.apache.logging.log4j.util.Strings;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.ApprovalService;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.approval.InMemoryApprovalStore;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.InMemoryMultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.stubbing.Answer;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

class CheckTokenEndpointTests {
    private IdentityZone defaultZone;
    private CheckTokenEndpoint endpoint;
    private OAuth2Authentication authentication;
    private UaaTokenServices tokenServices;
    private InMemoryMultitenantClientServices clientDetailsService;
    private final ApprovalStore approvalStore = new InMemoryApprovalStore();

    private final String userId = "12345";
    private final String userName = "olds";
    private final String userEmail = "olds@vmware.com";

    private String signerKey;

    private AuthorizationRequest authorizationRequest;
    private UaaUserPrototype uaaUserPrototype;
    private UaaUser user;
    private UaaClientDetails defaultClient;
    private Map<String, UaaClientDetails> clientDetailsStore;
    private List<GrantedAuthority> userAuthorities;
    private final IdentityZoneProvisioning zoneProvisioning = mock(IdentityZoneProvisioning.class);
    private RevocableTokenProvisioning tokenProvisioning;
    private HashMap<String, RevocableToken> tokenMap;

    private final MockHttpServletRequest request = new MockHttpServletRequest();

    IdentityZone zone;
    private UaaUserDatabase userDatabase;
    private TokenEndpointBuilder tokenEndpointBuilder;
    private TokenValidationService tokenValidationService;
    private Long nowMillis;
    private TimeService timeService;
    private IdentityZoneManager mockIdentityZoneManager;

    public static Stream<Arguments> data() {
        return Stream.of(
                arguments("""
                        -----BEGIN RSA PRIVATE KEY-----
                        MIIEowIBAAKCAQEA0m59l2u9iDnMbrXHfqkOrn2dVQ3vfBJqcDuFUK03d+1PZGbV
                        lNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7fYb3d8TjhV86Y997Fl4DBrxgM6KT
                        JOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQBLCl0vpcXBtFLMaSbpv1ozi8h7DJy
                        VZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDOkqwIn7Glry9n9Suxygbf8g5AzpWc
                        usZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPojfj9Cw2QICsc5+Pwf21fP+hzf+1W
                        SRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nIJwIDAQABAoIBAHPV9rSfzllq16op
                        zoNetIJBC5aCcU4vJQBbA2wBrgMKUyXFpdSheQphgY7GP/BJTYtifRiS9RzsHAYY
                        pAlTQEQ9Q4RekZAdd5r6rlsFrUzL7Xj/CVjNfQyHPhPocNqwrkxp4KrO5eL06qcw
                        UzT7UtnoiCdSLI7IL0hIgJZP8J1uPNdXH+kkDEHE9xzU1q0vsi8nBLlim+ioYfEa
                        Q/Q/ovMNviLKVs+ZUz+wayglDbCzsevuU+dh3Gmfc98DJw6n6iClpd4fDPqvhxUO
                        BDeQT1mFeHxexDse/kH9nygxT6E4wlU1sw0TQANcT6sHReyHT1TlwnWlCQzoR3l2
                        RmkzUsECgYEA8W/VIkfyYdUd5ri+yJ3iLdYF2tDvkiuzVmJeA5AK2KO1fNc7cSPK
                        /sShHruc0WWZKWiR8Tp3d1XwA2rHMFHwC78RsTds+NpROs3Ya5sWd5mvmpEBbL+z
                        cl3AU9NLHVvsZjogmgI9HIMTTl4ld7GDsFMt0qlCDztqG6W/iguQCx8CgYEA3x/j
                        UkP45/PaFWd5c1DkWvmfmi9UxrIM7KeyBtDExGIkffwBMWFMCWm9DODw14bpnqAA
                        jH5AhQCzVYaXIdp12b+1+eOOckYHwzjWOFpJ3nLgNK3wi067jVp0N0UfgV5nfYw/
                        +YoHfYRCGsM91fowh7wLcyPPwmSAbQAKwbOZKfkCgYEAnccDdZ+m2iA3pitdIiVr
                        RaDzuoeHx/IfBHjMD2/2ZpS1aZwOEGXfppZA5KCeXokSimj31rjqkWXrr4/8E6u4
                        PzTiDvm1kPq60r7qi4eSKx6YD15rm/G7ByYVJbKTB+CmoDekToDgBt3xo+kKeyna
                        cUQqUdyieunM8bxja4ca3ukCgYAfrDAhomJ30qa3eRvFYcs4msysH2HiXq30/g0I
                        aKQ12FSjyZ0FvHEFuQvMAzZM8erByKarStSvzJyoXFWhyZgHE+6qDUJQOF6ruKq4
                        DyEDQb1P3Q0TSVbYRunOWrKRM6xvJvSB4LUVfSvBDsv9TumKqwfZDVFVn9yXHHVq
                        b6sjSQKBgDkcyYkAjpOHoG3XKMw06OE4OKpP9N6qU8uZOuA8ZF9ZyR7vFf4bCsKv
                        QH+xY/4h8tgL+eASz5QWhj8DItm8wYGI5lKJr8f36jk0JLPUXODyDAeN6ekXY9LI
                        fudkijw0dnh28LJqbkFF5wLNtATzyCfzjp+czrPMn9uqLNKt/iVD
                        -----END RSA PRIVATE KEY-----
                        """, false),
                arguments("signing_key_does_not_affect_opaque_token", true)
        );
    }

    private final String alternateSignerKey = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIEowIBAAKCAQEAsLZaEu+98J6neClnaCBy82xg9/DdVgLuO4fr0X9N/nmzaJ1L
            vBmhBdRA8zCLMHQXQmNko7vAZa2/L+A1zQL110puyB4YeInE5lJmGuAADVE2s2ep
            dritrHKVVVv2eCucKRMbQSbhXG2YX0QLp0T4z35Mw3Pa2Q1EDKVinL0o6deW4cX6
            AyUhmqanUphIplQKDrSGp4Lk14aPz/05/IJFA73y5qHJEIlmvuH6RZTZC3H1X1Xs
            pEo2dLOKt9rpvBo4tQkBxG6ejTIAfyu4+1429Zuvn5VCTkKHKgRmSgo6totBrBjR
            1Y7U+k8A+8YbZh3TS4t09i9E4jEmSt7lSUhTjQIDAQABAoIBAF8Rm5/4bt1W3Y4d
            6E3ytyUSt5BsewddCEHqvAm3TYSMgOLVTPtjZme2a0LqaNemfSTwSCJ2Tenl8aeW
            HhuvbgdnOfZbipq+s7mdtuTageyoNp+KM3d1n6nY81I66Xx5KchHSTBh9Hg/Vexa
            tVJGHv2yWyYD3EdNhcCv8T+V3L8Aon3a38y+manNNnM/jI9BfOR2reUn6LWGo8S1
            kUP9CA9vnM1MpLyGONHoVSzzIh/TTOR108FWlQr++ez1OB/sjA66Us2P72yFwRdW
            Wq2KSP75/g21x9nXInMhKHMmeO9Wm2QfwXZRDTr/vJ4jvfwLdUl3CMfdMl0bHPNG
            jB36/8ECgYEA2HNGM53fOoxqPzdYGkWNJosaWyyNvyNxIUO6Mb8vB8jQUWus5hIR
            GkL7XBSOGKGOpPN5nkZ79DArXdBZh+cXBGPQ9EGtE8H1E2wTM2l+3Ez3mzFoCISH
            w/fj9pxm/eA+9GPzSJ95j+6zzpMkjhXYQQcGiJc1Y1RUvfWhs0mhhzkCgYEA0QBJ
            C70YqkBFUjCrgtvCZocTc3b3Mh+bF9R/Kn/CTKnF//NjPEr9zMfefhbxhyI+L0U6
            Y7gZHVP32pFXQwnDrD3FmPY50RqTNz4c0ey9v1eEOgOl369HV+E66XuL1A0XUnI4
            wD9QpsoT/WCCy2UG7iruEmkvVUncRsVZUDqHOvUCgYEAzQk9ae3VpP+YMbP6eECE
            Oguw9scYqwQmyUz/1tn08hnPBCHMkdBxdQAYXZx3EmwP1L9y6HR6PNFYczDHbs6A
            Zj8rlAWWr02fGzvYYG5Bpuwd7Vv64X6xoPh0cIqtoTZITHdV4Oh4XdjPaRLHoPSe
            etLt5HvgLeyXra4987j/EzkCgYBCMSjxQs5Q/VH3Gdr38sm61wTeCMt5YHEqNu6f
            cx8CULKYwWioa8e9138rx/Bur/Wp2u8HLgMmOrXAz08nuCv0nQu7yh+9jgEZ+d3+
            zk+6DemexhD+qvCZcIfL8ojye8LrJam7mVHdwRpboPlLmY98VrRXuGB5To8pCs+i
            jSbPEQKBgEbrOYmJ4p2Esse55Bs+NP+HVuYEOBcKUVHxBG2ILMqA2GjQWO886siu
            Fg9454+Y1xN9DT768RIqkadKXR4r4Tnu8SesrqqqsRub8+RCZFe/JRxEetRBfE3g
            xEo7mKPEF+x8IhJuw6m3kMc4nvFg30KzUKgspAJGPo6kwTVNdT/W
            -----END RSA PRIVATE KEY-----
            """;

    void initCheckTokenEndpointTests(String signerKey, boolean useOpaque) {
        this.signerKey = signerKey;
        setUp(useOpaque);
    }

    @AfterEach
    void after() {
        TestUtils.resetIdentityZoneHolder(null);
    }

    void setUp(boolean opaque) {
        zone = MultitenancyFixture.identityZone("id", "subdomain");
        defaultZone = IdentityZone.getUaa();

        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(defaultZone);
        clientDetailsService = new InMemoryMultitenantClientServices(mockIdentityZoneManager);

        TestUtils.resetIdentityZoneHolder(null);

        nowMillis = 10000L;
        timeService = mock(TimeService.class);
        when(timeService.getCurrentTimeMillis()).thenCallRealMethod().thenReturn(nowMillis);
        when(timeService.getCurrentDate()).thenCallRealMethod();
        userAuthorities = new ArrayList<>();
        userAuthorities.add(new SimpleGrantedAuthority("read"));
        userAuthorities.add(new SimpleGrantedAuthority("write"));
        userAuthorities.add(new SimpleGrantedAuthority("zones.myzone.admin"));
        userAuthorities.addAll(UaaAuthority.USER_AUTHORITIES);
        user = new UaaUser(
                userId,
                userName,
                "password",
                userEmail,
                userAuthorities,
                "GivenName",
                "FamilyName",
                new Date(nowMillis - 2000),
                new Date(nowMillis - 2000),
                OriginKeys.UAA,
                "externalId",
                false,
                IdentityZoneHolder.get().getId(),
                "salt",
                new Date(nowMillis - 2000));
        uaaUserPrototype = new UaaUserPrototype(user).withAuthorities(null);
        authorizationRequest = new AuthorizationRequest("client", Set.of("read"));
        authorizationRequest.setResourceIds(new HashSet<>(List.of("client", "scim")));
        Map<String, String> requestParameters = new HashMap<>();
        tokenProvisioning = mock(RevocableTokenProvisioning.class);
        if (opaque) {
            tokenMap = new HashMap<>();
            when(tokenProvisioning.create(any(), anyString())).thenAnswer(invocation -> {
                RevocableToken token = (RevocableToken) invocation.getArguments()[0];
                tokenMap.put(token.getTokenId(), token);
                return token;
            });
            when(tokenProvisioning.retrieve(anyString(), anyString())).thenAnswer(invocation -> {
                String id = (String) invocation.getArguments()[0];
                return tokenMap.get(id);
            });
            doAnswer((Answer<Void>) invocation -> {
                RevocableToken arg = (RevocableToken) invocation.getArguments()[1];
                tokenMap.put(arg.getTokenId(), arg);
                return null;
            }).when(tokenProvisioning).upsert(anyString(), any(), anyString());
            doAnswer((Answer<Void>) invocation -> {
                RevocableToken arg = (RevocableToken) invocation.getArguments()[0];
                tokenMap.put(arg.getTokenId(), arg);
                return null;
            }).when(tokenProvisioning).createIfNotExists(any(), anyString());

            requestParameters.put(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        }
        authorizationRequest.setRequestParameters(requestParameters);
        authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(),
                UaaAuthenticationTestFactory.getAuthentication(userId, userName, "olds@vmware.com"));

        configureDefaultZoneKeys(Map.of("testKey", signerKey));
        IdentityZoneHolder.set(defaultZone);
        when(zoneProvisioning.retrieve(IdentityZone.getUaaZoneId())).thenReturn(defaultZone);
        Date oneSecondAgo = new Date(nowMillis - 1000);
        Date thirtySecondsAhead = new Date(nowMillis + 30000);

        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("client")
                .setScope("read")
                .setExpiresAt(thirtySecondsAhead)
                .setStatus(ApprovalStatus.APPROVED)
                .setLastUpdatedAt(oneSecondAgo), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("client")
                .setScope("write")
                .setExpiresAt(thirtySecondsAhead)
                .setStatus(ApprovalStatus.APPROVED)
                .setLastUpdatedAt(oneSecondAgo), IdentityZoneHolder.get().getId());

        defaultClient = new UaaClientDetails("client", "scim, cc", "read, write", "authorization_code, password", "scim.read, scim.write, cat.pet", "http://localhost:8080/uaa");
        clientDetailsStore =
                Map.of(
                        "client",
                        defaultClient
                );
        clientDetailsService.setClientDetailsStore(zone.getId(), clientDetailsStore);
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), clientDetailsStore);
        assertThatNoException().isThrownBy(() -> tokenEndpointBuilder = new TokenEndpointBuilder("http://localhost:8080/uaa"));
        userDatabase = mock(UaaUserDatabase.class);
        KeyInfoService keyInfoService = new KeyInfoService("http://localhost:8080/uaa");
        tokenValidationService = new TokenValidationService(tokenProvisioning, tokenEndpointBuilder, userDatabase, clientDetailsService, keyInfoService);
        ApprovalService approvalService = new ApprovalService(timeService, approvalStore, mockIdentityZoneManager);
        tokenServices = new UaaTokenServices(
                mock(IdTokenCreator.class),
                tokenEndpointBuilder,
                clientDetailsService,
                tokenProvisioning,
                tokenValidationService,
                null,
                timeService,
                new TokenValidityResolver(new ClientAccessTokenValidity(clientDetailsService, mockIdentityZoneManager), Integer.MAX_VALUE, timeService),
                userDatabase,
                Sets.newHashSet(),
                IdentityZoneHolder.get().getConfig().getTokenPolicy(),
                keyInfoService,
                new IdTokenGranter(approvalService),
                approvalService);

        resetAndMockUserDatabase(userId, user);

        endpoint = new CheckTokenEndpoint(tokenServices, timeService);
    }

    private void configureDefaultZoneKeys(Map<String, String> keys) {
        IdentityZoneHolder.clear();
        IdentityZoneHolder.setProvisioning(zoneProvisioning);
        IdentityZoneConfiguration config = defaultZone.getConfig();
        TokenPolicy tokenPolicy = config.getTokenPolicy();
        tokenPolicy.setActiveKeyId(keys.keySet().stream().findFirst().get());
        tokenPolicy.setAccessTokenValidity(43200);
        tokenPolicy.setRefreshTokenValidity(2592000);
        tokenPolicy.setKeys(keys);
    }

    private void resetAndMockUserDatabase(String userId, UaaUser user) {
        reset(userDatabase);
        when(userDatabase.retrieveUserById(userId)).thenReturn(user);
        when(userDatabase.retrieveUserById(not(eq(userId)))).thenThrow(new UsernameNotFoundException("mock"));
        when(userDatabase.retrieveUserPrototypeById(userId)).thenReturn(uaaUserPrototype);
        when(userDatabase.retrieveUserPrototypeById(not(eq(userId)))).thenThrow(new UsernameNotFoundException("mock"));
    }

    @MethodSource("data")
    @ParameterizedTest
    void clientWildcard(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        UaaClientDetails client =
                new UaaClientDetails("client", "zones", "zones.*.admin", "authorization_code, password",
                        "scim.read, scim.write", "http://localhost:8080/uaa");
        client.setAutoApproveScopes(List.of("zones.*.admin"));
        Map<String, UaaClientDetails> aClientDetailsStore = Map.of("client", client);

        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), aClientDetailsStore);
        tokenServices.setClientDetailsService(clientDetailsService);

        authorizationRequest = new AuthorizationRequest("client", Set.of("zones.myzone.admin"));
        authorizationRequest.setResourceIds(new HashSet<>(List.of("client", "zones")));
        authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(),
                UaaAuthenticationTestFactory.getAuthentication(userId, userName, "olds@vmware.com"));

        endpoint.checkToken(tokenServices.createAccessToken(authentication).getValue(), List.of(), request);
    }

    @MethodSource("data")
    @ParameterizedTest
    void rejectInvalidVerifier(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        configureDefaultZoneKeys(Map.of("testKey", alternateSignerKey));

        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void rejectUserSaltChange(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        user = new UaaUser(
                userId,
                userName,
                "password",
                userEmail,
                userAuthorities,
                "GivenName",
                "FamilyName",
                new Date(nowMillis - 2000),
                new Date(nowMillis - 2000),
                OriginKeys.UAA,
                "externalId",
                false,
                IdentityZoneHolder.get().getId(),
                "changedsalt",
                new Date(nowMillis - 2000));
        resetAndMockUserDatabase(userId, user);
        assertThatExceptionOfType(TokenRevokedException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void rejectUserUsernameChange(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        user = new UaaUser(
                userId,
                "newUsername@test.org",
                "password",
                userEmail,
                userAuthorities,
                "GivenName",
                "FamilyName",
                new Date(nowMillis - 2000),
                new Date(nowMillis - 2000),
                OriginKeys.UAA,
                "externalId",
                false,
                IdentityZoneHolder.get().getId(),
                "salt",
                new Date(nowMillis - 2000));
        resetAndMockUserDatabase(userId, user);
        assertThatExceptionOfType(TokenRevokedException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void rejectUserEmailChange(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        user = new UaaUser(
                userId,
                userName,
                "password",
                "newEmail@test.org",
                userAuthorities,
                "GivenName",
                "FamilyName",
                new Date(nowMillis - 2000),
                new Date(nowMillis - 2000),
                OriginKeys.UAA,
                "externalId",
                false,
                IdentityZoneHolder.get().getId(),
                "salt",
                new Date(nowMillis - 2000));
        resetAndMockUserDatabase(userId, user);
        assertThatExceptionOfType(TokenRevokedException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void rejectUserPasswordChange(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        user = new UaaUser(
                userId,
                userName,
                "changedpassword",
                userEmail,
                userAuthorities,
                "GivenName",
                "FamilyName",
                new Date(nowMillis - 2000),
                new Date(nowMillis - 2000),
                OriginKeys.UAA,
                "externalId",
                false,
                IdentityZoneHolder.get().getId(),
                "salt",
                new Date(nowMillis - 2000));
        resetAndMockUserDatabase(userId, user);
        assertThatExceptionOfType(TokenRevokedException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void rejectClientSaltChange(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        defaultClient.addAdditionalInformation(ClientConstants.TOKEN_SALT, "changedsalt");
        assertThatExceptionOfType(TokenRevokedException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void rejectClientPasswordChange(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        defaultClient.setClientSecret("changedsecret");
        assertThatExceptionOfType(TokenRevokedException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    private static String missingScopeMessage(String... scopes) {
        return "Some requested scopes are missing: " + String.join(",", scopes);
    }

    @MethodSource("data")
    @ParameterizedTest
    void validateScopesNotPresent(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                Set.of("scim.read")).createOAuth2Request(), null);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        List<String> scopes = List.of("scim.write");
        String accessTokenValue = accessToken.getValue();
        assertThatThrownBy(() -> endpoint.checkToken(accessTokenValue, scopes, request))
                .isInstanceOf(InvalidScopeException.class)
                .hasMessage(missingScopeMessage("scim.write"));
    }

    @MethodSource("data")
    @ParameterizedTest
    void validateScopesMultipleNotPresent(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                List.of("cat.pet")).createOAuth2Request(), null);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        List<String> scopes = List.of("scim.write", "scim.read");
        String accessTokenValue = accessToken.getValue();
        assertThatThrownBy(() -> endpoint.checkToken(accessTokenValue, scopes, request))
                .isInstanceOf(InvalidScopeException.class)
                .hasMessage(missingScopeMessage("scim.write", "scim.read"));
    }

    @MethodSource("data")
    @ParameterizedTest
    void validateScopeSinglePresent(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                Set.of("scim.read")).createOAuth2Request(), null);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        endpoint.checkToken(accessToken.getValue(), List.of("scim.read"), request);
    }

    @MethodSource("data")
    @ParameterizedTest
    void validateScopesMultiplePresent(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                List.of("scim.read", "scim.write")).createOAuth2Request(), null);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        endpoint.checkToken(accessToken.getValue(), List.of("scim.write", "scim.read"), request);
    }

    @MethodSource("data")
    @ParameterizedTest
    void validateScopesSomeNotPresent(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                List.of("scim.read", "scim.write")).createOAuth2Request(), null);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        List<String> scopes = List.of("scim.read", "ponies.ride");
        String accessTokenValue = accessToken.getValue();
        assertThatThrownBy(() -> endpoint.checkToken(accessTokenValue, scopes, request))
                .isInstanceOf(InvalidScopeException.class)
                .hasMessage(missingScopeMessage("ponies.ride"));
    }

    @MethodSource("data")
    @ParameterizedTest
    void revokingScopesFromUser_invalidatesToken(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        user = user.authorities(UaaAuthority.NONE_AUTHORITIES);
        resetAndMockUserDatabase(userId, user);
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void revokingScopesFromClient_invalidatesToken(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        defaultClient = new UaaClientDetails("client", "scim, cc", "write", "authorization_code, password", "scim.read, scim.write", "http://localhost:8080/uaa");
        clientDetailsStore = Map.of("client", defaultClient);
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), clientDetailsStore);
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void revokingAuthoritiesFromClients_invalidatesToken(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        defaultClient = new UaaClientDetails("client", "scim, cc", "write,read", "authorization_code, password", "scim.write", "http://localhost:8080/uaa");
        clientDetailsStore = Map.of(
                "client",
                defaultClient
        );
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), clientDetailsStore);
        resetAndMockUserDatabase(userId, user);
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                Set.of("scim.read")).createOAuth2Request(), null);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void switchVerifierKey(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        configureDefaultZoneKeys(Map.of("testKey", alternateSignerKey));
        OAuth2AccessToken alternateToken = tokenServices.createAccessToken(authentication);
        List<String> scopes = List.of();

        String alternateTokenValue = alternateToken.getValue();
        assertThatThrownBy(() -> endpoint.checkToken(alternateTokenValue, scopes, request))
                .isInstanceOf(InvalidTokenException.class);

        String accessTokenValue = accessToken.getValue();
        assertThatThrownBy(() -> endpoint.checkToken(accessTokenValue, scopes, request))
                .isInstanceOf(InvalidTokenException.class);
    }

    @MethodSource("data")
    @ParameterizedTest
    void clientAddSecret(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        String firstClientSecret = "oldsecret";
        String secondClientSecret = "newsecret";
        defaultClient.setClientSecret(firstClientSecret);
        when(timeService.getCurrentTimeMillis()).thenCallRealMethod().thenReturn(1000L);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        defaultClient.setClientSecret(firstClientSecret + " " + secondClientSecret);
        endpoint.checkToken(accessToken.getValue(), List.of(), request);
        when(timeService.getCurrentTimeMillis()).thenCallRealMethod().thenReturn(1000L);
        accessToken = tokenServices.createAccessToken(authentication);
        endpoint.checkToken(accessToken.getValue(), List.of(), request);
    }

    @MethodSource("data")
    @ParameterizedTest
    void clientDeleteSecret(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        String firstClientSecret = "oldsecret";
        String secondClientSecret = "newsecret";

        defaultClient.setClientSecret(firstClientSecret + " " + secondClientSecret);
        when(timeService.getCurrentTimeMillis()).thenCallRealMethod().thenReturn(1000L);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        endpoint.checkToken(accessToken.getValue(), List.of(), request);

        defaultClient.setClientSecret(secondClientSecret);
        when(timeService.getCurrentTimeMillis()).thenCallRealMethod().thenReturn(1000L);
        accessToken = tokenServices.createAccessToken(authentication);
        endpoint.checkToken(accessToken.getValue(), List.of(), request);
    }

    @MethodSource("data")
    @ParameterizedTest
    void userIdInResult(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(result.getUserName()).isEqualTo("olds");
        assertThat(result.getUserId()).isEqualTo("12345");
        assertThat(result.getExtAttr()).as("external attributes must not present").isNull();
    }

    @MethodSource("data")
    @ParameterizedTest
    void extAttrInResult(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        tokenServices.setUaaTokenEnhancer(new TestTokenEnhancer());
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(result.getExtAttr()).as("external attributes not present").isNotNull()
                .containsEntry("purpose", "test");
    }

    @MethodSource("data")
    @ParameterizedTest
    void issuerInResults(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        ReflectionTestUtils.setField(tokenEndpointBuilder, "issuer", "http://some.other.issuer");
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims claims = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(claims.getIss()).as("iss field is not present").isNotNull()
                .isEqualTo("http://some.other.issuer/oauth/token");
    }

    @MethodSource("data")
    @ParameterizedTest
    void issuerInResultsInNonDefaultZone(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        try {
            IdentityZoneHolder.set(zone);
            ReflectionTestUtils.setField(tokenEndpointBuilder, "issuer", "http://some.other.issuer");
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
            Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
            assertThat(result.getIss()).as("iss field is not present").isNotNull()
                    .isEqualTo("http://subdomain.some.other.issuer/oauth/token");
        } finally {
            IdentityZoneHolder.clear();
        }
    }

    @MethodSource("data")
    @ParameterizedTest
    void zoneRejectsTokenSignedWithKeyFromOtherZone(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() -> {

            try {
                zone.getConfig().getTokenPolicy().setKeys(Map.of("testKey",
                        """
                                -----BEGIN RSA PRIVATE KEY-----
                                MIIBOgIBAAJAcEJMJ3ZT4GgdxipJe4uXvRQFfSpOneGjHfFTLjECMd0OkNtIWoIU
                                8OisQRmhBDdXk2owne2SGJcqsVN/pd9pMQIDAQABAkAV/KY1xHNBLKNIQNgLnpel
                                rNo2XabwPVVZc/66uVaYtVSwQjOxlo7mIzp77dpiM6o0kT4v3/9eyfKZte4uB/pR
                                AiEAtF6MXrNeqEoJVCQ6LOUFgc1HtS1tqHBk6Fo3WO44ctMCIQCfVI3bTCY09F82
                                TgIHtKdBtKzCGS56EzqbnbNodAoJawIhAJ25dCw31BV7sI6oo0qw9tDcDtGrKRI7
                                PrJEedPFdQ1LAiEAklI6fHywUc1iayK0ppL3T1Y3mYE6t41VM3hePLzkQsUCIFjE
                                NEUwGQmhVae7YpA8dgs0wFjsfdX15q+4wwWKu9oN
                                -----END RSA PRIVATE KEY-----"""));
                IdentityZoneHolder.set(zone);
                KeyInfoService keyInfoService = new KeyInfoService("http://localhost:8080/uaa");
                ApprovalService approvalService = new ApprovalService(timeService, approvalStore, mockIdentityZoneManager);
                tokenServices = new UaaTokenServices(
                        mock(IdTokenCreator.class),
                        tokenEndpointBuilder,
                        clientDetailsService,
                        tokenProvisioning,
                        tokenValidationService,
                        null,
                        timeService,
                        new TokenValidityResolver(new ClientAccessTokenValidity(clientDetailsService, mockIdentityZoneManager), Integer.MAX_VALUE, timeService),
                        userDatabase,
                        Sets.newHashSet(),
                        zone.getConfig().getTokenPolicy(),
                        keyInfoService,
                        new IdTokenGranter(approvalService),
                        approvalService);
                endpoint.checkToken(accessToken.getValue(), List.of(), request);
            } finally {
                IdentityZoneHolder.clear();
            }
        });
    }

    @MethodSource("data")
    @ParameterizedTest
    void zoneValidatesTokenSignedWithOwnKey(String signerKey, boolean useOpaque) throws Exception {

        initCheckTokenEndpointTests(signerKey, useOpaque);

        try {
            zone.getConfig().getTokenPolicy().setKeys(Map.of("zoneKey",
                    """
                            -----BEGIN RSA PRIVATE KEY-----
                            MIIBOgIBAAJAcEJMJ3ZT4GgdxipJe4uXvRQFfSpOneGjHfFTLjECMd0OkNtIWoIU
                            8OisQRmhBDdXk2owne2SGJcqsVN/pd9pMQIDAQABAkAV/KY1xHNBLKNIQNgLnpel
                            rNo2XabwPVVZc/66uVaYtVSwQjOxlo7mIzp77dpiM6o0kT4v3/9eyfKZte4uB/pR
                            AiEAtF6MXrNeqEoJVCQ6LOUFgc1HtS1tqHBk6Fo3WO44ctMCIQCfVI3bTCY09F82
                            TgIHtKdBtKzCGS56EzqbnbNodAoJawIhAJ25dCw31BV7sI6oo0qw9tDcDtGrKRI7
                            PrJEedPFdQ1LAiEAklI6fHywUc1iayK0ppL3T1Y3mYE6t41VM3hePLzkQsUCIFjE
                            NEUwGQmhVae7YpA8dgs0wFjsfdX15q+4wwWKu9oN
                            -----END RSA PRIVATE KEY-----"""));
            IdentityZoneHolder.set(zone);
            tokenEndpointBuilder = new TokenEndpointBuilder("http://some.other.issuer");
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
            endpoint.checkToken(accessToken.getValue(), List.of(), request);
        } finally {
            IdentityZoneHolder.clear();
        }

    }

    @MethodSource("data")
    @ParameterizedTest
    void zoneValidatesTokenSignedWithInactiveKey(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        HashMap<String, String> keys = new HashMap<>();
        keys.put("oldKey", """
                -----BEGIN RSA PRIVATE KEY-----
                MIIBOgIBAAJAcEJMJ3ZT4GgdxipJe4uXvRQFfSpOneGjHfFTLjECMd0OkNtIWoIU
                8OisQRmhBDdXk2owne2SGJcqsVN/pd9pMQIDAQABAkAV/KY1xHNBLKNIQNgLnpel
                rNo2XabwPVVZc/66uVaYtVSwQjOxlo7mIzp77dpiM6o0kT4v3/9eyfKZte4uB/pR
                AiEAtF6MXrNeqEoJVCQ6LOUFgc1HtS1tqHBk6Fo3WO44ctMCIQCfVI3bTCY09F82
                TgIHtKdBtKzCGS56EzqbnbNodAoJawIhAJ25dCw31BV7sI6oo0qw9tDcDtGrKRI7
                PrJEedPFdQ1LAiEAklI6fHywUc1iayK0ppL3T1Y3mYE6t41VM3hePLzkQsUCIFjE
                NEUwGQmhVae7YpA8dgs0wFjsfdX15q+4wwWKu9oN
                -----END RSA PRIVATE KEY-----""");
        configureDefaultZoneKeys(keys);
        tokenEndpointBuilder = new TokenEndpointBuilder("http://some.other.issuer");
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        keys.put("newKey", "nc978y78o3cg5i7env587geehn89mcehgc46");
        configureDefaultZoneKeys(keys);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setActiveKeyId("newKey");

        endpoint.checkToken(accessToken.getValue(), List.of(), request);
    }

    @MethodSource("data")
    @ParameterizedTest
    void zoneValidatesTokenSignedWithRemovedKey(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        HashMap<String, String> keys = new HashMap<>();
        keys.put("oldKey", """
                -----BEGIN RSA PRIVATE KEY-----
                MIIBOgIBAAJAcEJMJ3ZT4GgdxipJe4uXvRQFfSpOneGjHfFTLjECMd0OkNtIWoIU
                8OisQRmhBDdXk2owne2SGJcqsVN/pd9pMQIDAQABAkAV/KY1xHNBLKNIQNgLnpel
                rNo2XabwPVVZc/66uVaYtVSwQjOxlo7mIzp77dpiM6o0kT4v3/9eyfKZte4uB/pR
                AiEAtF6MXrNeqEoJVCQ6LOUFgc1HtS1tqHBk6Fo3WO44ctMCIQCfVI3bTCY09F82
                TgIHtKdBtKzCGS56EzqbnbNodAoJawIhAJ25dCw31BV7sI6oo0qw9tDcDtGrKRI7
                PrJEedPFdQ1LAiEAklI6fHywUc1iayK0ppL3T1Y3mYE6t41VM3hePLzkQsUCIFjE
                NEUwGQmhVae7YpA8dgs0wFjsfdX15q+4wwWKu9oN
                -----END RSA PRIVATE KEY-----""");
        configureDefaultZoneKeys(keys);
        tokenEndpointBuilder = new TokenEndpointBuilder("http://some.other.issuer");
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        keys.remove("oldKey");
        keys.put("newKey", "nc978y78o3cg5i7env587geehn89mcehgc46");
        configureDefaultZoneKeys(keys);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setActiveKeyId("newKey");

        List<String> scopes = List.of();
        String accessTokenValue = accessToken.getValue();
        assertThatThrownBy(() -> endpoint.checkToken(accessTokenValue, scopes, request))
                .isInstanceOf(InvalidTokenException.class);
    }

    @MethodSource("data")
    @ParameterizedTest
    void defaultZoneRejectsTokenSignedWithOtherZoneKey(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        zone.getConfig().getTokenPolicy().setKeys(Map.of("zoneKey",
                """
                        -----BEGIN RSA PRIVATE KEY-----
                        MIIBOgIBAAJAcEJMJ3ZT4GgdxipJe4uXvRQFfSpOneGjHfFTLjECMd0OkNtIWoIU
                        8OisQRmhBDdXk2owne2SGJcqsVN/pd9pMQIDAQABAkAV/KY1xHNBLKNIQNgLnpel
                        rNo2XabwPVVZc/66uVaYtVSwQjOxlo7mIzp77dpiM6o0kT4v3/9eyfKZte4uB/pR
                        AiEAtF6MXrNeqEoJVCQ6LOUFgc1HtS1tqHBk6Fo3WO44ctMCIQCfVI3bTCY09F82
                        TgIHtKdBtKzCGS56EzqbnbNodAoJawIhAJ25dCw31BV7sI6oo0qw9tDcDtGrKRI7
                        PrJEedPFdQ1LAiEAklI6fHywUc1iayK0ppL3T1Y3mYE6t41VM3hePLzkQsUCIFjE
                        NEUwGQmhVae7YpA8dgs0wFjsfdX15q+4wwWKu9oN
                        -----END RSA PRIVATE KEY-----"""));
        IdentityZoneHolder.set(zone);
        tokenServices.setTokenEndpointBuilder(new TokenEndpointBuilder("http://some.other.issuer"));
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        IdentityZoneHolder.clear();
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void validateAudParameter(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        List<String> aud = result.getAud();
        assertThat(aud)
                .hasSize(2)
                .contains("scim", "client");
    }

    void internal_byDefaultQueryStringIsAllowed() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        request.setQueryString("token=" + accessToken.getValue());
        request.setParameter("token", accessToken.getValue());
        Claims claims = endpoint.checkToken(request);
        assertThat(claims).isNotNull();
    }

    @MethodSource("data")
    @ParameterizedTest
    void by_default_query_string_is_allowed(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        internal_byDefaultQueryStringIsAllowed();
    }

    void internal_ByDefaultGetIsAllowed() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        request.setQueryString("token=" + accessToken.getValue());
        request.setParameter("token", accessToken.getValue());
        endpoint.checkToken(request);
    }

    @MethodSource("data")
    @ParameterizedTest
    void by_default_get_is_allowed(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        internal_ByDefaultGetIsAllowed();
    }

    @MethodSource("data")
    @ParameterizedTest
    void disable_query_string(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        endpoint.setAllowQueryString(false);
        assertThatExceptionOfType(HttpRequestMethodNotSupportedException.class).isThrownBy(this::internal_byDefaultQueryStringIsAllowed);
    }

    @MethodSource("data")
    @ParameterizedTest
    void disable_get_method(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        endpoint.setAllowQueryString(false);
        assertThatExceptionOfType(HttpRequestMethodNotSupportedException.class).isThrownBy(this::internal_ByDefaultGetIsAllowed);
    }

    @MethodSource("data")
    @ParameterizedTest
    void clientId(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(result.getAzp()).isEqualTo("client");
        assertThat(result.getCid()).isEqualTo("client");
        assertThat(result.getClientId()).isEqualTo("client");
    }

    @MethodSource("data")
    @ParameterizedTest
    void validateAuthTime(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(result.getAuthTime()).isNotNull();
    }

    @MethodSource("data")
    @ParameterizedTest
    void revokedToken_ThrowsTokenRevokedException(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        setUp(useOpaque);
        when(tokenProvisioning.retrieve(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));

        IdentityZoneHolder.get().getConfig().getTokenPolicy().setJwtRevocable(true);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertThatExceptionOfType(TokenRevokedException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void validateIssuedAtIsSmallerThanExpiredAt(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        Integer iat = result.getIat();
        assertThat(iat).isNotNull();
        Long exp = result.getExp();
        assertThat(exp).isNotNull()
                .isGreaterThan(iat);
    }

    @MethodSource("data")
    @ParameterizedTest
    void emailInResult(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(result.getEmail()).isEqualTo("olds@vmware.com");
    }

    @MethodSource("data")
    @ParameterizedTest
    void clientIdInResult(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(result.getClientId()).isEqualTo("client");
    }

    @MethodSource("data")
    @ParameterizedTest
    void clientIdInAud(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(result.getAud()).contains("client");
    }

    @MethodSource("data")
    @ParameterizedTest
    void expiryResult(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        int expiresIn = 60 * 60 * 12;
        assertThat(expiresIn + Instant.now().toEpochMilli() / 1000).isGreaterThanOrEqualTo(result.getExp());
    }

    @MethodSource("data")
    @ParameterizedTest
    void userAuthoritiesNotInResult(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(result.getAuthorities()).isNull();
    }

    @MethodSource("data")
    @ParameterizedTest
    void expiredToken(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        UaaClientDetails clientDetails = new UaaClientDetails("client", "scim, cc", "read, write",
                "authorization_code, password", "scim.read, scim.write", "http://localhost:8080/uaa");
        Integer validitySeconds = 1;
        clientDetails.setAccessTokenValiditySeconds(validitySeconds);
        Map<String, UaaClientDetails> aClientDetailsStore = Map.of("client", clientDetails);
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), aClientDetailsStore);
        tokenServices.setClientDetailsService(clientDetailsService);
        when(timeService.getCurrentTimeMillis()).thenReturn(1000L);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        when(timeService.getCurrentTimeMillis()).thenReturn(nowMillis + validitySeconds.longValue() * 1000 + 1L);
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void deniedApprovals(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Date oneSecondAgo = new Date(nowMillis - 1000);
        Date thirtySecondsAhead = new Date(nowMillis + 30000);
        approvalStore.revokeApproval(new Approval()
                .setUserId(userId)
                .setClientId("client")
                .setScope("read")
                .setExpiresAt(thirtySecondsAhead)
                .setStatus(ApprovalStatus.APPROVED)
                .setLastUpdatedAt(oneSecondAgo), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("client")
                .setScope("read")
                .setExpiresAt(thirtySecondsAhead)
                .setStatus(ApprovalStatus.DENIED)
                .setLastUpdatedAt(oneSecondAgo), IdentityZoneHolder.get().getId());
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void expiredApprovals(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        approvalStore.revokeApproval(new Approval()
                .setUserId(userId)
                .setClientId("client")
                .setScope("read")
                .setExpiresAt(new Date(nowMillis))
                .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        approvalStore.addApproval(new Approval()
                .setUserId(userId)
                .setClientId("client")
                .setScope("read")
                .setExpiresAt(new Date(nowMillis))
                .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());

        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                endpoint.checkToken(accessToken.getValue(), List.of(), request));
    }

    @MethodSource("data")
    @ParameterizedTest
    void clientOnly(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                Set.of("scim.read")).createOAuth2Request(), null);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(result.getClientId()).isEqualTo("client");
        assertThat(result.getUserId()).isNull();
    }

    @MethodSource("data")
    @ParameterizedTest
    void validAuthorities(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        Map<String, String> azAttributes = new HashMap<>();
        azAttributes.put("external_group", "domain\\group1");
        azAttributes.put("external_id", "abcd1234");
        Map<String, Object> azAuthorities = new HashMap<>();
        azAuthorities.put("az_attr", azAttributes);
        String azAuthoritiesJson = JsonUtils.writeValueAsString(azAuthorities);
        Map<String, String> requestParameters = new HashMap<>();
        requestParameters.put("authorities", azAuthoritiesJson);
        authorizationRequest.setRequestParameters(requestParameters);
        authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(),
                UaaAuthenticationTestFactory.getAuthentication(userId, userName, "olds@vmware.com"));
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(azAttributes).isEqualTo(result.getAzAttr());
    }

    @MethodSource("data")
    @ParameterizedTest
    void invalidAuthoritiesNested(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        Map<String, Object> nestedAttributes = new HashMap<>();
        nestedAttributes.put("nested_group", "true");
        nestedAttributes.put("nested_id", "1234");
        Map<String, Object> azAttributes = new HashMap<>();
        azAttributes.put("external_id", nestedAttributes);
        Map<String, Object> azAuthorities = new HashMap<>();
        azAuthorities.put("az_attr", azAttributes);
        String azAuthoritiesJson = JsonUtils.writeValueAsString(azAuthorities);
        Map<String, String> requestParameters = new HashMap<>();
        requestParameters.put("authorities", azAuthoritiesJson);
        authorizationRequest.setRequestParameters(requestParameters);
        authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(),
                UaaAuthenticationTestFactory.getAuthentication(userId, userName, "olds@vmware.com"));
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(result.getAzAttr()).isNull();
    }

    @MethodSource("data")
    @ParameterizedTest
    void emptyAuthorities(String signerKey, boolean useOpaque) throws Exception {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        Map<String, String> azAttributes = new HashMap<>();
        azAttributes.put("external_group", "domain\\group1");
        azAttributes.put("external_id", "abcd1234");
        Map<String, Object> azAuthorities = new HashMap<>();
        azAuthorities.put("any_attr", azAttributes);
        String azAuthoritiesJson = JsonUtils.writeValueAsString(azAuthorities);
        Map<String, String> requestParameters = new HashMap<>();
        requestParameters.put("authorities", azAuthoritiesJson);
        authorizationRequest.setRequestParameters(requestParameters);
        authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(),
                UaaAuthenticationTestFactory.getAuthentication(userId, userName, "olds@vmware.com"));
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), List.of(), request);
        assertThat(result.getAzAttr()).isNull();
    }

    @MethodSource("data")
    @ParameterizedTest
    void nullAndEmptyToken(String signerKey, boolean useOpaque) {
        initCheckTokenEndpointTests(signerKey, useOpaque);
        List<String> scopes = List.of();
        assertThatThrownBy(() -> endpoint.checkToken(null, scopes, request))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessage("Token parameter must be set");

        assertThatThrownBy(() -> endpoint.checkToken(Strings.EMPTY, scopes, request))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessage("Token parameter must be set");
    }
}
