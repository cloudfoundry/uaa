/*******************************************************************************
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
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.ApprovalService;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.approval.InMemoryApprovalStore;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenGranter;
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
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.stubbing.Answer;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class CheckTokenEndpointTests {
    private IdentityZone defaultZone;
    private CheckTokenEndpoint endpoint;
    private OAuth2Authentication authentication;
    private UaaTokenServices tokenServices;
    private InMemoryMultitenantClientServices clientDetailsService;
    private ApprovalStore approvalStore = new InMemoryApprovalStore();

    private String userId = "12345";
    private String userName = "olds";
    private String userEmail = "olds@vmware.com";

    private String signerKey;
    private boolean useOpaque;

    private AuthorizationRequest authorizationRequest = null;
    private UaaUserPrototype uaaUserPrototype;
    private UaaUser user;
    private BaseClientDetails defaultClient;
    private Map<String, BaseClientDetails> clientDetailsStore;
    private List<GrantedAuthority> userAuthorities;
    private IdentityZoneProvisioning zoneProvisioning = mock(IdentityZoneProvisioning.class);
    private RevocableTokenProvisioning tokenProvisioning;
    private HashMap<String, RevocableToken> tokenMap;

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private MockHttpServletRequest request = new MockHttpServletRequest();

    IdentityZone zone;
    private UaaUserDatabase userDatabase;
    private TokenEndpointBuilder tokenEndpointBuilder;
    private TokenValidationService tokenValidationService;
    private Long nowMillis;
    private TimeService timeService;
    private IdentityZoneManager mockIdentityZoneManager;

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {
                        "-----BEGIN RSA PRIVATE KEY-----\n" +
                                "MIIEowIBAAKCAQEA0m59l2u9iDnMbrXHfqkOrn2dVQ3vfBJqcDuFUK03d+1PZGbV\n" +
                                "lNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7fYb3d8TjhV86Y997Fl4DBrxgM6KT\n" +
                                "JOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQBLCl0vpcXBtFLMaSbpv1ozi8h7DJy\n" +
                                "VZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDOkqwIn7Glry9n9Suxygbf8g5AzpWc\n" +
                                "usZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPojfj9Cw2QICsc5+Pwf21fP+hzf+1W\n" +
                                "SRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nIJwIDAQABAoIBAHPV9rSfzllq16op\n" +
                                "zoNetIJBC5aCcU4vJQBbA2wBrgMKUyXFpdSheQphgY7GP/BJTYtifRiS9RzsHAYY\n" +
                                "pAlTQEQ9Q4RekZAdd5r6rlsFrUzL7Xj/CVjNfQyHPhPocNqwrkxp4KrO5eL06qcw\n" +
                                "UzT7UtnoiCdSLI7IL0hIgJZP8J1uPNdXH+kkDEHE9xzU1q0vsi8nBLlim+ioYfEa\n" +
                                "Q/Q/ovMNviLKVs+ZUz+wayglDbCzsevuU+dh3Gmfc98DJw6n6iClpd4fDPqvhxUO\n" +
                                "BDeQT1mFeHxexDse/kH9nygxT6E4wlU1sw0TQANcT6sHReyHT1TlwnWlCQzoR3l2\n" +
                                "RmkzUsECgYEA8W/VIkfyYdUd5ri+yJ3iLdYF2tDvkiuzVmJeA5AK2KO1fNc7cSPK\n" +
                                "/sShHruc0WWZKWiR8Tp3d1XwA2rHMFHwC78RsTds+NpROs3Ya5sWd5mvmpEBbL+z\n" +
                                "cl3AU9NLHVvsZjogmgI9HIMTTl4ld7GDsFMt0qlCDztqG6W/iguQCx8CgYEA3x/j\n" +
                                "UkP45/PaFWd5c1DkWvmfmi9UxrIM7KeyBtDExGIkffwBMWFMCWm9DODw14bpnqAA\n" +
                                "jH5AhQCzVYaXIdp12b+1+eOOckYHwzjWOFpJ3nLgNK3wi067jVp0N0UfgV5nfYw/\n" +
                                "+YoHfYRCGsM91fowh7wLcyPPwmSAbQAKwbOZKfkCgYEAnccDdZ+m2iA3pitdIiVr\n" +
                                "RaDzuoeHx/IfBHjMD2/2ZpS1aZwOEGXfppZA5KCeXokSimj31rjqkWXrr4/8E6u4\n" +
                                "PzTiDvm1kPq60r7qi4eSKx6YD15rm/G7ByYVJbKTB+CmoDekToDgBt3xo+kKeyna\n" +
                                "cUQqUdyieunM8bxja4ca3ukCgYAfrDAhomJ30qa3eRvFYcs4msysH2HiXq30/g0I\n" +
                                "aKQ12FSjyZ0FvHEFuQvMAzZM8erByKarStSvzJyoXFWhyZgHE+6qDUJQOF6ruKq4\n" +
                                "DyEDQb1P3Q0TSVbYRunOWrKRM6xvJvSB4LUVfSvBDsv9TumKqwfZDVFVn9yXHHVq\n" +
                                "b6sjSQKBgDkcyYkAjpOHoG3XKMw06OE4OKpP9N6qU8uZOuA8ZF9ZyR7vFf4bCsKv\n" +
                                "QH+xY/4h8tgL+eASz5QWhj8DItm8wYGI5lKJr8f36jk0JLPUXODyDAeN6ekXY9LI\n" +
                                "fudkijw0dnh28LJqbkFF5wLNtATzyCfzjp+czrPMn9uqLNKt/iVD\n" +
                                "-----END RSA PRIVATE KEY-----\n", false
                },
                {
                        "signing_key_does_not_affect_opaque_token", true
                },
        });
    }

    private String alternateSignerKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEowIBAAKCAQEAsLZaEu+98J6neClnaCBy82xg9/DdVgLuO4fr0X9N/nmzaJ1L\n" +
            "vBmhBdRA8zCLMHQXQmNko7vAZa2/L+A1zQL110puyB4YeInE5lJmGuAADVE2s2ep\n" +
            "dritrHKVVVv2eCucKRMbQSbhXG2YX0QLp0T4z35Mw3Pa2Q1EDKVinL0o6deW4cX6\n" +
            "AyUhmqanUphIplQKDrSGp4Lk14aPz/05/IJFA73y5qHJEIlmvuH6RZTZC3H1X1Xs\n" +
            "pEo2dLOKt9rpvBo4tQkBxG6ejTIAfyu4+1429Zuvn5VCTkKHKgRmSgo6totBrBjR\n" +
            "1Y7U+k8A+8YbZh3TS4t09i9E4jEmSt7lSUhTjQIDAQABAoIBAF8Rm5/4bt1W3Y4d\n" +
            "6E3ytyUSt5BsewddCEHqvAm3TYSMgOLVTPtjZme2a0LqaNemfSTwSCJ2Tenl8aeW\n" +
            "HhuvbgdnOfZbipq+s7mdtuTageyoNp+KM3d1n6nY81I66Xx5KchHSTBh9Hg/Vexa\n" +
            "tVJGHv2yWyYD3EdNhcCv8T+V3L8Aon3a38y+manNNnM/jI9BfOR2reUn6LWGo8S1\n" +
            "kUP9CA9vnM1MpLyGONHoVSzzIh/TTOR108FWlQr++ez1OB/sjA66Us2P72yFwRdW\n" +
            "Wq2KSP75/g21x9nXInMhKHMmeO9Wm2QfwXZRDTr/vJ4jvfwLdUl3CMfdMl0bHPNG\n" +
            "jB36/8ECgYEA2HNGM53fOoxqPzdYGkWNJosaWyyNvyNxIUO6Mb8vB8jQUWus5hIR\n" +
            "GkL7XBSOGKGOpPN5nkZ79DArXdBZh+cXBGPQ9EGtE8H1E2wTM2l+3Ez3mzFoCISH\n" +
            "w/fj9pxm/eA+9GPzSJ95j+6zzpMkjhXYQQcGiJc1Y1RUvfWhs0mhhzkCgYEA0QBJ\n" +
            "C70YqkBFUjCrgtvCZocTc3b3Mh+bF9R/Kn/CTKnF//NjPEr9zMfefhbxhyI+L0U6\n" +
            "Y7gZHVP32pFXQwnDrD3FmPY50RqTNz4c0ey9v1eEOgOl369HV+E66XuL1A0XUnI4\n" +
            "wD9QpsoT/WCCy2UG7iruEmkvVUncRsVZUDqHOvUCgYEAzQk9ae3VpP+YMbP6eECE\n" +
            "Oguw9scYqwQmyUz/1tn08hnPBCHMkdBxdQAYXZx3EmwP1L9y6HR6PNFYczDHbs6A\n" +
            "Zj8rlAWWr02fGzvYYG5Bpuwd7Vv64X6xoPh0cIqtoTZITHdV4Oh4XdjPaRLHoPSe\n" +
            "etLt5HvgLeyXra4987j/EzkCgYBCMSjxQs5Q/VH3Gdr38sm61wTeCMt5YHEqNu6f\n" +
            "cx8CULKYwWioa8e9138rx/Bur/Wp2u8HLgMmOrXAz08nuCv0nQu7yh+9jgEZ+d3+\n" +
            "zk+6DemexhD+qvCZcIfL8ojye8LrJam7mVHdwRpboPlLmY98VrRXuGB5To8pCs+i\n" +
            "jSbPEQKBgEbrOYmJ4p2Esse55Bs+NP+HVuYEOBcKUVHxBG2ILMqA2GjQWO886siu\n" +
            "Fg9454+Y1xN9DT768RIqkadKXR4r4Tnu8SesrqqqsRub8+RCZFe/JRxEetRBfE3g\n" +
            "xEo7mKPEF+x8IhJuw6m3kMc4nvFg30KzUKgspAJGPo6kwTVNdT/W\n" +
            "-----END RSA PRIVATE KEY-----\n";

    public CheckTokenEndpointTests(String signerKey, boolean useOpaque) {
        this.signerKey = signerKey;
        this.useOpaque = useOpaque;
    }

    @Before
    public void setUp() throws Exception {
        setUp(useOpaque);
    }

    @After
    public void after() {
        TestUtils.resetIdentityZoneHolder(null);
    }

    public void setUp(boolean opaque) throws Exception {
        zone = MultitenancyFixture.identityZone("id", "subdomain");
        defaultZone = IdentityZone.getUaa();

        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(defaultZone);
        clientDetailsService = new InMemoryMultitenantClientServices(mockIdentityZoneManager);

        TestUtils.resetIdentityZoneHolder(null);

        nowMillis = 10000L;
        timeService = mock(TimeService.class);
        when(timeService.getCurrentTimeMillis()).thenReturn(nowMillis);
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
        authorizationRequest = new AuthorizationRequest("client", Collections.singleton("read"));
        authorizationRequest.setResourceIds(new HashSet<>(Arrays.asList("client", "scim")));
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
                RevocableToken arg = (RevocableToken)invocation.getArguments()[1];
                tokenMap.put(arg.getTokenId(), arg);
                return null;
            }).when(tokenProvisioning).upsert(anyString(), any(), anyString());
            doAnswer((Answer<Void>) invocation -> {
                RevocableToken arg = (RevocableToken)invocation.getArguments()[0];
                tokenMap.put(arg.getTokenId(), arg);
                return null;
            }).when(tokenProvisioning).createIfNotExists(any(), anyString());


            requestParameters.put(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        }
        authorizationRequest.setRequestParameters(requestParameters);
        authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(),
                UaaAuthenticationTestFactory.getAuthentication(userId, userName, "olds@vmware.com"));

        configureDefaultZoneKeys(Collections.singletonMap("testKey", signerKey));
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

        defaultClient = new BaseClientDetails("client", "scim, cc", "read, write", "authorization_code, password", "scim.read, scim.write, cat.pet", "http://localhost:8080/uaa");
        clientDetailsStore =
                Collections.singletonMap(
                        "client",
                        defaultClient
                );
        clientDetailsService.setClientDetailsStore(zone.getId(), clientDetailsStore);
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), clientDetailsStore);

        tokenEndpointBuilder = new TokenEndpointBuilder("http://localhost:8080/uaa");
        userDatabase = mock(UaaUserDatabase.class);
        KeyInfoService keyInfoService = new KeyInfoService("http://localhost:8080/uaa");
        tokenValidationService = new TokenValidationService(tokenProvisioning, tokenEndpointBuilder, userDatabase, clientDetailsService, keyInfoService);
        ApprovalService approvalService = new ApprovalService(timeService, approvalStore);
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
        when(userDatabase.retrieveUserById(eq(userId))).thenReturn(user);
        when(userDatabase.retrieveUserById(not(eq(userId)))).thenThrow(new UsernameNotFoundException("mock"));
        when(userDatabase.retrieveUserPrototypeById(eq(userId))).thenReturn(uaaUserPrototype);
        when(userDatabase.retrieveUserPrototypeById(not(eq(userId)))).thenThrow(new UsernameNotFoundException("mock"));
    }

    @Test
    public void testClientWildcard() throws Exception {
        BaseClientDetails client =
                new BaseClientDetails("client", "zones", "zones.*.admin", "authorization_code, password",
                        "scim.read, scim.write", "http://localhost:8080/uaa");
        client.setAutoApproveScopes(Collections.singletonList("zones.*.admin"));
        Map<String, BaseClientDetails> clientDetailsStore = Collections.singletonMap("client", client);

        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), clientDetailsStore);
        tokenServices.setClientDetailsService(clientDetailsService);

        authorizationRequest = new AuthorizationRequest("client", Collections.singleton("zones.myzone.admin"));
        authorizationRequest.setResourceIds(new HashSet<>(Arrays.asList("client", "zones")));
        authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(),
                UaaAuthenticationTestFactory.getAuthentication(userId, userName, "olds@vmware.com"));

        endpoint.checkToken(tokenServices.createAccessToken(authentication).getValue(), Collections.emptyList(), request);
    }

    @Test()
    public void testRejectInvalidVerifier() throws Exception {
        try {
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
            configureDefaultZoneKeys(Collections.singletonMap("testKey", alternateSignerKey));
            endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);

            fail("Token validation should fail");
        } catch (InvalidTokenException ignored) {
        }
    }

    @Test(expected = TokenRevokedException.class)
    public void testRejectUserSaltChange() throws Exception {
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
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test(expected = TokenRevokedException.class)
    public void testRejectUserUsernameChange() throws Exception {
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
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test(expected = TokenRevokedException.class)
    public void testRejectUserEmailChange() throws Exception {
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
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }


    @Test(expected = TokenRevokedException.class)
    public void testRejectUserPasswordChange() throws Exception {
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
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test(expected = TokenRevokedException.class)
    public void testRejectClientSaltChange() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        defaultClient.addAdditionalInformation(ClientConstants.TOKEN_SALT, "changedsalt");
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test(expected = TokenRevokedException.class)
    public void testRejectClientPasswordChange() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        defaultClient.setClientSecret("changedsecret");
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    private static String missingScopeMessage(String... scopes) {
        return "Some requested scopes are missing: " + String.join(",", scopes);
    }

    @Test(expected = InvalidScopeException.class)
    public void testValidateScopesNotPresent() throws Exception {
        try {
            authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                    Collections.singleton("scim.read")).createOAuth2Request(), null);
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

            endpoint.checkToken(accessToken.getValue(), Collections.singletonList("scim.write"), request);
        } catch (InvalidScopeException ex) {
            assertEquals(missingScopeMessage("scim.write"), ex.getMessage());
            throw ex;
        }
    }

    @Test(expected = InvalidScopeException.class)
    public void testValidateScopesMultipleNotPresent() throws Exception {
        try {
            authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                    Collections.singletonList("cat.pet")).createOAuth2Request(), null);
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

            endpoint.checkToken(accessToken.getValue(), Arrays.asList("scim.write", "scim.read"), request);
        } catch (InvalidScopeException ex) {
            assertEquals(missingScopeMessage("scim.write", "scim.read"), ex.getMessage());
            throw ex;
        }
    }

    @Test
    public void testValidateScopeSinglePresent() throws Exception {
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                Collections.singleton("scim.read")).createOAuth2Request(), null);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        endpoint.checkToken(accessToken.getValue(), Collections.singletonList("scim.read"), request);
    }

    @Test
    public void testValidateScopesMultiplePresent() throws Exception {
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                Arrays.asList("scim.read", "scim.write")).createOAuth2Request(), null);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        endpoint.checkToken(accessToken.getValue(), Arrays.asList("scim.write", "scim.read"), request);
    }

    @Test(expected = InvalidScopeException.class)
    public void testValidateScopesSomeNotPresent() throws Exception {
        try {
            authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                    Arrays.asList("scim.read", "scim.write")).createOAuth2Request(), null);
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

            endpoint.checkToken(accessToken.getValue(), Arrays.asList("scim.read", "ponies.ride"), request);
        } catch (InvalidScopeException ex) {
            assertEquals(missingScopeMessage("ponies.ride"), ex.getMessage());
            throw ex;
        }
    }

    @Test(expected = InvalidTokenException.class)
    public void revokingScopesFromUser_invalidatesToken() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        user = user.authorities(UaaAuthority.NONE_AUTHORITIES);
        resetAndMockUserDatabase(userId, user);

        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test(expected = InvalidTokenException.class)
    public void revokingScopesFromClient_invalidatesToken() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        defaultClient = new BaseClientDetails("client", "scim, cc", "write", "authorization_code, password", "scim.read, scim.write", "http://localhost:8080/uaa");
        clientDetailsStore = Collections.singletonMap("client", defaultClient);
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), clientDetailsStore);

        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test(expected = InvalidTokenException.class)
    public void revokingAuthoritiesFromClients_invalidatesToken() throws Exception {
        defaultClient = new BaseClientDetails("client", "scim, cc", "write,read", "authorization_code, password", "scim.write", "http://localhost:8080/uaa");
        clientDetailsStore = Collections.singletonMap(
                "client",
                defaultClient
        );
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), clientDetailsStore);
        resetAndMockUserDatabase(userId, user);
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                Collections.singleton("scim.read")).createOAuth2Request(), null);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test
    public void testSwitchVerifierKey() throws Exception {
        try {
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
            configureDefaultZoneKeys(Collections.singletonMap("testKey", alternateSignerKey));
            OAuth2AccessToken alternateToken = tokenServices.createAccessToken(authentication);
            endpoint.checkToken(alternateToken.getValue(), Collections.emptyList(), request);
            endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
            fail("Token validation should fail");
        } catch (InvalidTokenException ex) {
            assertTrue("expected - rewrite to use a rule", true);
        }
    }

    @Test
    public void testClientAddSecret() throws Exception {
        String firstClientSecret = "oldsecret";
        String secondClientSecret = "newsecret";
        defaultClient.setClientSecret(firstClientSecret);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        defaultClient.setClientSecret(firstClientSecret + " " + secondClientSecret);
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        accessToken = tokenServices.createAccessToken(authentication);
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test
    public void testClientDeleteSecret() throws Exception {
        String firstClientSecret = "oldsecret";
        String secondClientSecret = "newsecret";

        defaultClient.setClientSecret(firstClientSecret + " " + secondClientSecret);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);

        defaultClient.setClientSecret(secondClientSecret);
        accessToken = tokenServices.createAccessToken(authentication);
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test
    public void testUserIdInResult() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertEquals("olds", result.getUserName());
        assertEquals("12345", result.getUserId());
        assertNull("external attributes must not present", result.getExtAttr());
    }

    @Test
    public void testExtAttrInResult() throws Exception {
        tokenServices.setUaaTokenEnhancer(new TestTokenEnhancer());
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertNotNull("external attributes not present", result.getExtAttr());
        assertEquals("test", result.getExtAttr().get("purpose"));
    }

    @Test
    public void testIssuerInResults() throws Exception {
        ReflectionTestUtils.setField(tokenEndpointBuilder, "issuer", "http://some.other.issuer");
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims claims = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertNotNull("iss field is not present", claims.getIss());
        assertEquals("http://some.other.issuer/oauth/token", claims.getIss());
    }

    @Test
    public void testIssuerInResultsInNonDefaultZone() throws Exception {
        try {
            IdentityZoneHolder.set(zone);
            ReflectionTestUtils.setField(tokenEndpointBuilder, "issuer", "http://some.other.issuer");
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
            Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
            assertNotNull("iss field is not present", result.getIss());
            assertEquals("http://subdomain.some.other.issuer/oauth/token", result.getIss());
        } finally {
            IdentityZoneHolder.clear();
        }
    }

    @Test(expected = InvalidTokenException.class)
    public void testZoneRejectsTokenSignedWithKeyFromOtherZone() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        try {
            zone.getConfig().getTokenPolicy().setKeys(Collections.singletonMap("testKey",
                    "-----BEGIN RSA PRIVATE KEY-----\n" +
                            "MIIBOgIBAAJAcEJMJ3ZT4GgdxipJe4uXvRQFfSpOneGjHfFTLjECMd0OkNtIWoIU\n" +
                            "8OisQRmhBDdXk2owne2SGJcqsVN/pd9pMQIDAQABAkAV/KY1xHNBLKNIQNgLnpel\n" +
                            "rNo2XabwPVVZc/66uVaYtVSwQjOxlo7mIzp77dpiM6o0kT4v3/9eyfKZte4uB/pR\n" +
                            "AiEAtF6MXrNeqEoJVCQ6LOUFgc1HtS1tqHBk6Fo3WO44ctMCIQCfVI3bTCY09F82\n" +
                            "TgIHtKdBtKzCGS56EzqbnbNodAoJawIhAJ25dCw31BV7sI6oo0qw9tDcDtGrKRI7\n" +
                            "PrJEedPFdQ1LAiEAklI6fHywUc1iayK0ppL3T1Y3mYE6t41VM3hePLzkQsUCIFjE\n" +
                            "NEUwGQmhVae7YpA8dgs0wFjsfdX15q+4wwWKu9oN\n" +
                            "-----END RSA PRIVATE KEY-----"));
            IdentityZoneHolder.set(zone);
            tokenServices.setTokenPolicy(zone.getConfig().getTokenPolicy());
            endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        } finally {
            IdentityZoneHolder.clear();
        }

    }

    @Test
    public void testZoneValidatesTokenSignedWithOwnKey() throws Exception {

        try {
            zone.getConfig().getTokenPolicy().setKeys(Collections.singletonMap("zoneKey",
                    "-----BEGIN RSA PRIVATE KEY-----\n" +
                            "MIIBOgIBAAJAcEJMJ3ZT4GgdxipJe4uXvRQFfSpOneGjHfFTLjECMd0OkNtIWoIU\n" +
                            "8OisQRmhBDdXk2owne2SGJcqsVN/pd9pMQIDAQABAkAV/KY1xHNBLKNIQNgLnpel\n" +
                            "rNo2XabwPVVZc/66uVaYtVSwQjOxlo7mIzp77dpiM6o0kT4v3/9eyfKZte4uB/pR\n" +
                            "AiEAtF6MXrNeqEoJVCQ6LOUFgc1HtS1tqHBk6Fo3WO44ctMCIQCfVI3bTCY09F82\n" +
                            "TgIHtKdBtKzCGS56EzqbnbNodAoJawIhAJ25dCw31BV7sI6oo0qw9tDcDtGrKRI7\n" +
                            "PrJEedPFdQ1LAiEAklI6fHywUc1iayK0ppL3T1Y3mYE6t41VM3hePLzkQsUCIFjE\n" +
                            "NEUwGQmhVae7YpA8dgs0wFjsfdX15q+4wwWKu9oN\n" +
                            "-----END RSA PRIVATE KEY-----"));
            IdentityZoneHolder.set(zone);
            tokenEndpointBuilder = new TokenEndpointBuilder("http://some.other.issuer");
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
            endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        } finally {
            IdentityZoneHolder.clear();
        }

    }

    @Test
    public void testZoneValidatesTokenSignedWithInactiveKey() throws Exception {
        HashMap<String, String> keys = new HashMap<>();
        keys.put("oldKey", "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIBOgIBAAJAcEJMJ3ZT4GgdxipJe4uXvRQFfSpOneGjHfFTLjECMd0OkNtIWoIU\n" +
                "8OisQRmhBDdXk2owne2SGJcqsVN/pd9pMQIDAQABAkAV/KY1xHNBLKNIQNgLnpel\n" +
                "rNo2XabwPVVZc/66uVaYtVSwQjOxlo7mIzp77dpiM6o0kT4v3/9eyfKZte4uB/pR\n" +
                "AiEAtF6MXrNeqEoJVCQ6LOUFgc1HtS1tqHBk6Fo3WO44ctMCIQCfVI3bTCY09F82\n" +
                "TgIHtKdBtKzCGS56EzqbnbNodAoJawIhAJ25dCw31BV7sI6oo0qw9tDcDtGrKRI7\n" +
                "PrJEedPFdQ1LAiEAklI6fHywUc1iayK0ppL3T1Y3mYE6t41VM3hePLzkQsUCIFjE\n" +
                "NEUwGQmhVae7YpA8dgs0wFjsfdX15q+4wwWKu9oN\n" +
                "-----END RSA PRIVATE KEY-----");
        configureDefaultZoneKeys(keys);
        tokenEndpointBuilder = new TokenEndpointBuilder("http://some.other.issuer");
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        keys.put("newKey", "nc978y78o3cg5i7env587geehn89mcehgc46");
        configureDefaultZoneKeys(keys);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setActiveKeyId("newKey");

        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test
    public void testZoneValidatesTokenSignedWithRemovedKey() throws Exception {
        try {
            HashMap<String, String> keys = new HashMap<>();
            keys.put("oldKey", "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "MIIBOgIBAAJAcEJMJ3ZT4GgdxipJe4uXvRQFfSpOneGjHfFTLjECMd0OkNtIWoIU\n" +
                    "8OisQRmhBDdXk2owne2SGJcqsVN/pd9pMQIDAQABAkAV/KY1xHNBLKNIQNgLnpel\n" +
                    "rNo2XabwPVVZc/66uVaYtVSwQjOxlo7mIzp77dpiM6o0kT4v3/9eyfKZte4uB/pR\n" +
                    "AiEAtF6MXrNeqEoJVCQ6LOUFgc1HtS1tqHBk6Fo3WO44ctMCIQCfVI3bTCY09F82\n" +
                    "TgIHtKdBtKzCGS56EzqbnbNodAoJawIhAJ25dCw31BV7sI6oo0qw9tDcDtGrKRI7\n" +
                    "PrJEedPFdQ1LAiEAklI6fHywUc1iayK0ppL3T1Y3mYE6t41VM3hePLzkQsUCIFjE\n" +
                    "NEUwGQmhVae7YpA8dgs0wFjsfdX15q+4wwWKu9oN\n" +
                    "-----END RSA PRIVATE KEY-----");
            configureDefaultZoneKeys(keys);
            tokenEndpointBuilder = new TokenEndpointBuilder("http://some.other.issuer");
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

            keys.remove("oldKey");
            keys.put("newKey", "nc978y78o3cg5i7env587geehn89mcehgc46");
            configureDefaultZoneKeys(keys);
            IdentityZoneHolder.get().getConfig().getTokenPolicy().setActiveKeyId("newKey");

            endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);

            fail("Token validation should fail");
        } catch (InvalidTokenException ex) {
            assertTrue("expected - rewrite to use a rule", true);
        }
    }

    @Test(expected = InvalidTokenException.class)
    public void testDefaultZoneRejectsTokenSignedWithOtherZoneKey() throws Exception {
        zone.getConfig().getTokenPolicy().setKeys(Collections.singletonMap("zoneKey",
                "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "MIIBOgIBAAJAcEJMJ3ZT4GgdxipJe4uXvRQFfSpOneGjHfFTLjECMd0OkNtIWoIU\n" +
                        "8OisQRmhBDdXk2owne2SGJcqsVN/pd9pMQIDAQABAkAV/KY1xHNBLKNIQNgLnpel\n" +
                        "rNo2XabwPVVZc/66uVaYtVSwQjOxlo7mIzp77dpiM6o0kT4v3/9eyfKZte4uB/pR\n" +
                        "AiEAtF6MXrNeqEoJVCQ6LOUFgc1HtS1tqHBk6Fo3WO44ctMCIQCfVI3bTCY09F82\n" +
                        "TgIHtKdBtKzCGS56EzqbnbNodAoJawIhAJ25dCw31BV7sI6oo0qw9tDcDtGrKRI7\n" +
                        "PrJEedPFdQ1LAiEAklI6fHywUc1iayK0ppL3T1Y3mYE6t41VM3hePLzkQsUCIFjE\n" +
                        "NEUwGQmhVae7YpA8dgs0wFjsfdX15q+4wwWKu9oN\n" +
                        "-----END RSA PRIVATE KEY-----"));
        IdentityZoneHolder.set(zone);
        tokenServices.setTokenEndpointBuilder(new TokenEndpointBuilder("http://some.other.issuer"));
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        IdentityZoneHolder.clear();
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test
    public void testValidateAudParameter() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        List<String> aud = result.getAud();
        assertEquals(2, aud.size());
        assertTrue(aud.contains("scim"));
        assertTrue(aud.contains("client"));
    }

    @Test
    public void by_default_query_string_is_allowed() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        request.setQueryString("token=" + accessToken.getValue());
        request.setParameter("token", accessToken.getValue());
        Claims claims = endpoint.checkToken(request);
        assertNotNull(claims);
    }

    @Test
    public void by_default_get_is_allowed() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        request.setQueryString("token=" + accessToken.getValue());
        request.setParameter("token", accessToken.getValue());
        endpoint.checkToken(request);
    }

    @Test(expected = HttpRequestMethodNotSupportedException.class)
    public void disable_query_string() throws Exception {
        endpoint.setAllowQueryString(false);
        by_default_query_string_is_allowed();
    }

    @Test(expected = HttpRequestMethodNotSupportedException.class)
    public void disable_get_method() throws Exception {
        endpoint.setAllowQueryString(false);
        by_default_get_is_allowed();
    }

    @Test
    public void testClientId() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertEquals("client", result.getAzp());
        assertEquals("client", result.getCid());
        assertEquals("client", result.getClientId());
    }

    @Test
    public void validateAuthTime() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertNotNull(result.getAuthTime());
    }

    @Test(expected = TokenRevokedException.class)
    public void revokedToken_ThrowsTokenRevokedException() throws Exception {
        setUp();
        when(tokenProvisioning.retrieve(anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));

        IdentityZoneHolder.get().getConfig().getTokenPolicy().setJwtRevocable(true);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test
    public void validateIssuedAtIsSmallerThanExpiredAt() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        Integer iat = result.getIat();
        assertNotNull(iat);
        Long exp = result.getExp();
        assertNotNull(exp);
        assertTrue(iat < exp);
    }


    @Test
    public void testEmailInResult() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertEquals("olds@vmware.com", result.getEmail());
    }

    @Test
    public void testClientIdInResult() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertEquals("client", result.getClientId());
    }

    @Test
    public void testClientIdInAud() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertTrue(result.getAud().contains("client"));
    }


    @Test
    public void testExpiryResult() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        int expiresIn = 60 * 60 * 12;
        assertTrue(expiresIn + nowMillis / 1000 >= result.getExp());
    }

    @Test
    public void testUserAuthoritiesNotInResult() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertNull(result.getAuthorities());
    }

    @Test
    public void testClientAuthoritiesNotInResult() throws Exception {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertNull(result.getAuthorities());
    }

    @Test(expected = InvalidTokenException.class)
    public void testExpiredToken() throws Exception {
        BaseClientDetails clientDetails = new BaseClientDetails("client", "scim, cc", "read, write",
                "authorization_code, password", "scim.read, scim.write", "http://localhost:8080/uaa");
        Integer validitySeconds = 1;
        clientDetails.setAccessTokenValiditySeconds(validitySeconds);
        Map<String, BaseClientDetails> clientDetailsStore = Collections.singletonMap("client", clientDetails);
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), clientDetailsStore);
        tokenServices.setClientDetailsService(clientDetailsService);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        when(timeService.getCurrentTimeMillis()).thenReturn(nowMillis + validitySeconds.longValue() * 1000 + 1L);
        endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
    }

    @Test(expected = InvalidTokenException.class)
    public void testDeniedApprovals() throws Exception {
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
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertNull(result.getAuthorities());
    }

    @Test(expected = InvalidTokenException.class)
    public void testExpiredApprovals() throws Exception {
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
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertNull(result.getAuthorities());
    }

    @Test
    public void testClientOnly() throws Exception {
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                Collections.singleton("scim.read")).createOAuth2Request(), null);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertEquals("client", result.getClientId());
        assertNull(result.getUserId());
    }

    @Test
    public void testValidAuthorities() throws Exception {
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
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertEquals(result.getAzAttr(), azAttributes);
    }

    @Test
    public void testInvalidAuthoritiesNested() throws Exception {
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
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertNull(result.getAzAttr());
    }

    @Test
    public void testEmptyAuthorities() throws Exception {
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
        Claims result = endpoint.checkToken(accessToken.getValue(), Collections.emptyList(), request);
        assertNull(result.getAzAttr());
    }
}
