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

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.oauth.approval.InMemoryApprovalStore;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.AdditionalMatchers;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class CheckTokenEndpointTests {

    private CheckTokenEndpoint endpoint = new CheckTokenEndpoint();

    private OAuth2Authentication authentication;

    private int expiresIn = 60 * 60 * 12;

    private OAuth2AccessToken accessToken = null;

    private UaaTokenServices tokenServices = new UaaTokenServices();

    private InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

    private ApprovalStore approvalStore = new InMemoryApprovalStore();

    private String userId = "12345";
    private String userName = "olds";
    private String userEmail = "olds@vmware.com";

    private String signerKey;
    private String verifierKey;

    private AuthorizationRequest authorizationRequest = null;

    private UaaUser user;

    private UaaUserDatabase userDatabase = null;

    private BaseClientDetails defaultClient;

    private Map<String, ? extends ClientDetails> clientDetailsStore;
    private List userAuthorities;

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
            {
                "abc",
                "abc"
            },
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
                "-----END RSA PRIVATE KEY-----\n",
                "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0m59l2u9iDnMbrXHfqkO\n" +
                "rn2dVQ3vfBJqcDuFUK03d+1PZGbVlNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7\n" +
                "fYb3d8TjhV86Y997Fl4DBrxgM6KTJOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQB\n" +
                "LCl0vpcXBtFLMaSbpv1ozi8h7DJyVZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDO\n" +
                "kqwIn7Glry9n9Suxygbf8g5AzpWcusZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPo\n" +
                "jfj9Cw2QICsc5+Pwf21fP+hzf+1WSRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nI\n" +
                "JwIDAQAB\n" +
                "-----END PUBLIC KEY-----"
            },
        });
    }


    private String alternateVerifierKey = "-----BEGIN RSA PUBLIC KEY-----\n" +
        "MIIBCgKCAQEAsLZaEu+98J6neClnaCBy82xg9/DdVgLuO4fr0X9N/nmzaJ1LvBmh\n" +
        "BdRA8zCLMHQXQmNko7vAZa2/L+A1zQL110puyB4YeInE5lJmGuAADVE2s2epdrit\n" +
        "rHKVVVv2eCucKRMbQSbhXG2YX0QLp0T4z35Mw3Pa2Q1EDKVinL0o6deW4cX6AyUh\n" +
        "mqanUphIplQKDrSGp4Lk14aPz/05/IJFA73y5qHJEIlmvuH6RZTZC3H1X1XspEo2\n" +
        "dLOKt9rpvBo4tQkBxG6ejTIAfyu4+1429Zuvn5VCTkKHKgRmSgo6totBrBjR1Y7U\n" +
        "+k8A+8YbZh3TS4t09i9E4jEmSt7lSUhTjQIDAQAB\n" +
        "-----END RSA PUBLIC KEY-----";

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

    private SignerProvider signerProvider = null;

    public CheckTokenEndpointTests(String signerKey, String verifierKey) {
        this.signerKey = signerKey;
        this.verifierKey = verifierKey;
    }

    @Before
    public void setUp() {
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
                new Date(System.currentTimeMillis() - 2000),
                new Date(System.currentTimeMillis() - 2000),
                OriginKeys.UAA,
                "externalId",
                false,
                IdentityZoneHolder.get().getId(),
                "salt",
                new Date(System.currentTimeMillis() - 2000));
        mockUserDatabase(userId, user);
        authorizationRequest = new AuthorizationRequest("client", Collections.singleton("read"));
        authorizationRequest.setResourceIds(new HashSet<>(Arrays.asList("client","scim")));
        Map<String,String> requestParameters = new HashMap<>();
        authorizationRequest.setRequestParameters(requestParameters);
        authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(),
                        UaaAuthenticationTestFactory.getAuthentication(userId, userName, "olds@vmware.com"));

        signerProvider = new SignerProvider();
        signerProvider.setSigningKey(signerKey);
        signerProvider.setVerifierKey(verifierKey);
        tokenServices.setSignerProvider(signerProvider);
        endpoint.setTokenServices(tokenServices);
        Date oneSecondAgo = new Date(System.currentTimeMillis() - 1000);
        Date thirtySecondsAhead = new Date(System.currentTimeMillis() + 30000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId("client")
            .setScope("read")
            .setExpiresAt(thirtySecondsAhead)
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(oneSecondAgo));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId("client")
            .setScope("write")
            .setExpiresAt(thirtySecondsAhead)
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(oneSecondAgo));
        tokenServices.setApprovalStore(approvalStore);
        tokenServices.setTokenPolicy(new TokenPolicy(43200, 2592000));

        defaultClient = new BaseClientDetails("client", "scim, cc", "read, write", "authorization_code, password","scim.read, scim.write", "http://localhost:8080/uaa");
        clientDetailsStore =
                Collections.singletonMap(
                        "client",
                        defaultClient
                );
        clientDetailsService.setClientDetailsStore(clientDetailsStore);
        tokenServices.setClientDetailsService(clientDetailsService);

        accessToken = tokenServices.createAccessToken(authentication);
    }

    protected void mockUserDatabase(String userId, UaaUser user) {
        userDatabase = Mockito.mock(UaaUserDatabase.class);
        Mockito.when(userDatabase.retrieveUserById(Matchers.eq(userId))).thenReturn(user);
        Mockito.when(userDatabase.retrieveUserById(AdditionalMatchers.not(Matchers.eq(userId)))).thenThrow(new UsernameNotFoundException("mock"));
        tokenServices.setUserDatabase(userDatabase);
    }

    @Test
    public void testClientWildcard() throws Exception {
        BaseClientDetails theclient = new BaseClientDetails("client", "zones", "zones.*.admin", "authorization_code, password",
            "scim.read, scim.write", "http://localhost:8080/uaa");
        theclient.setAutoApproveScopes(Arrays.asList("zones.*.admin"));
        Map<String, ? extends ClientDetails> clientDetailsStore = Collections.singletonMap("client", theclient);

        clientDetailsService.setClientDetailsStore(clientDetailsStore);
        tokenServices.setClientDetailsService(clientDetailsService);

        authorizationRequest = new AuthorizationRequest("client", Collections.singleton("zones.myzone.admin"));
        authorizationRequest.setResourceIds(new HashSet<>(Arrays.asList("client","zones")));
        authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(),
            UaaAuthenticationTestFactory.getAuthentication(userId, userName, "olds@vmware.com"));

        accessToken = tokenServices.createAccessToken(authentication);

        endpoint.checkToken(accessToken.getValue());
    }

    @Test(expected = InvalidTokenException.class)
    public void testRejectInvalidIssuer() {
        tokenServices.setIssuer("http://some.other.issuer");
        endpoint.checkToken(accessToken.getValue());
    }

    @Test(expected = InvalidTokenException.class)
    public void testRejectInvalidVerifier() throws Exception {
        signerProvider.setSigningKey(alternateSignerKey);
        signerProvider.setVerifierKey(alternateVerifierKey);
        signerProvider.afterPropertiesSet();
        endpoint.checkToken(accessToken.getValue());
    }

    @Test(expected = TokenRevokedException.class)
    public void testRejectUserSaltChange() throws Exception {
        user = new UaaUser(
            userId,
            userName,
            "password",
            userEmail,
            userAuthorities,
            "GivenName",
            "FamilyName",
            new Date(System.currentTimeMillis() - 2000),
            new Date(System.currentTimeMillis() - 2000),
            OriginKeys.UAA,
            "externalId",
            false,
            IdentityZoneHolder.get().getId(),
            "changedsalt",
            new Date(System.currentTimeMillis() - 2000));
        mockUserDatabase(userId, user);
        endpoint.checkToken(accessToken.getValue());
    }

    @Test(expected = TokenRevokedException.class)
    public void testRejectUserUsernameChange() throws Exception {
        user = new UaaUser(
            userId,
            "newUsername@test.org",
            "password",
            userEmail,
            userAuthorities,
            "GivenName",
            "FamilyName",
            new Date(System.currentTimeMillis() - 2000),
            new Date(System.currentTimeMillis() - 2000),
            OriginKeys.UAA,
            "externalId",
            false,
            IdentityZoneHolder.get().getId(),
            "salt",
            new Date(System.currentTimeMillis() - 2000));
        mockUserDatabase(userId, user);
        endpoint.checkToken(accessToken.getValue());
    }

    @Test(expected = TokenRevokedException.class)
    public void testRejectUserEmailChange() throws Exception {
        user = new UaaUser(
            userId,
            userName,
            "password",
            "newEmail@test.org",
            userAuthorities,
            "GivenName",
            "FamilyName",
            new Date(System.currentTimeMillis() - 2000),
            new Date(System.currentTimeMillis() - 2000),
            OriginKeys.UAA,
            "externalId",
            false,
            IdentityZoneHolder.get().getId(),
            "salt",
            new Date(System.currentTimeMillis() - 2000));
        mockUserDatabase(userId, user);
        endpoint.checkToken(accessToken.getValue());
    }



    @Test(expected = TokenRevokedException.class)
    public void testRejectUserPasswordChange() throws Exception {
        user = new UaaUser(
            userId,
            userName,
            "changedpassword",
            userEmail,
            userAuthorities,
            "GivenName",
            "FamilyName",
            new Date(System.currentTimeMillis() - 2000),
            new Date(System.currentTimeMillis() - 2000),
            OriginKeys.UAA,
            "externalId",
            false,
            IdentityZoneHolder.get().getId(),
            "salt",
            new Date(System.currentTimeMillis() - 2000));

        mockUserDatabase(userId,user);
        endpoint.checkToken(accessToken.getValue());
    }

    @Test(expected = TokenRevokedException.class)
    public void testRejectClientSaltChange() throws Exception {
        defaultClient.addAdditionalInformation(ClientConstants.TOKEN_SALT, "changedsalt");
        endpoint.checkToken(accessToken.getValue());
    }

    @Test(expected = TokenRevokedException.class)
    public void testRejectClientPasswordChange() throws Exception {
        defaultClient.setClientSecret("changedsecret");
        endpoint.checkToken(accessToken.getValue());
    }

    @Test(expected = InvalidTokenException.class)
    public void revokingScopesFromUser_invalidatesToken() throws Exception {
        user = user.authorities(UaaAuthority.NONE_AUTHORITIES);
        mockUserDatabase(userId, user);
        endpoint.checkToken(accessToken.getValue());
    }

    @Test(expected = InvalidTokenException.class)
    public void revokingScopesFromClient_invalidatesToken() throws Exception {
        defaultClient = new BaseClientDetails("client", "scim, cc", "write", "authorization_code, password","scim.read, scim.write", "http://localhost:8080/uaa");
        clientDetailsStore = Collections.singletonMap(
                        "client",
                        defaultClient
                );
        clientDetailsService.setClientDetailsStore(clientDetailsStore);
        endpoint.checkToken(accessToken.getValue());
    }

    @Test(expected = InvalidTokenException.class)
    public void revokingAuthoritiesFromClients_invalidatesToken() throws Exception {
        defaultClient = new BaseClientDetails("client", "scim, cc", "write,read", "authorization_code, password","scim.write", "http://localhost:8080/uaa");
        clientDetailsStore = Collections.singletonMap(
                "client",
                defaultClient
        );
        clientDetailsService.setClientDetailsStore(clientDetailsStore);
        mockUserDatabase(userId, user);
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                Collections.singleton("scim.read")).createOAuth2Request(), null);
        accessToken = tokenServices.createAccessToken(authentication);
        endpoint.checkToken(accessToken.getValue());
    }

    @Test
    public void testSwitchVerifierKey() throws Exception {
        signerProvider.setSigningKey(alternateSignerKey);
        signerProvider.setVerifierKey(alternateVerifierKey);
        signerProvider.afterPropertiesSet();
        OAuth2AccessToken alternateToken = tokenServices.createAccessToken(authentication);
        endpoint.checkToken(alternateToken.getValue());
        try {
            endpoint.checkToken(accessToken.getValue());
            fail();
        } catch (InvalidTokenException x) {

        }
    }

    @Test
    public void testUserIdInResult() {
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertEquals("olds", result.getUserName());
        assertEquals("12345", result.getUserId());
    }

    @Test
    public void testIssuerInResults() throws Exception {
        tokenServices.setIssuer("http://some.other.issuer");
        tokenServices.afterPropertiesSet();
        accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertNotNull("iss field is not present", result.getIss());
        assertEquals("http://some.other.issuer/oauth/token",result.getIss());
    }

    @Test
    public void testIssuerInResultsInNonDefaultZone() throws Exception {
        try {
            IdentityZone zone = MultitenancyFixture.identityZone("id", "subdomain");
            IdentityZoneHolder.set(zone);
            tokenServices.setIssuer("http://some.other.issuer");
            tokenServices.afterPropertiesSet();
            accessToken = tokenServices.createAccessToken(authentication);
            Claims result = endpoint.checkToken(accessToken.getValue());
            assertNotNull("iss field is not present", result.getIss());
            assertEquals("http://subdomain.some.other.issuer/oauth/token", result.getIss());
        } finally {
            IdentityZoneHolder.clear();
        }

    }

    @Test
    public void testValidateAudParameter() {
        Claims result = endpoint.checkToken(accessToken.getValue());
        List<String> aud = result.getAud();
        assertEquals(2, aud.size());
        assertTrue(aud.contains("scim"));
        assertTrue(aud.contains("client"));
    }

    @Test
    public void testClientId() {
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertEquals("client", result.getAzp());
        assertEquals("client", result.getCid());
        assertEquals("client", result.getClientId());
    }

    @Test
    public void validateAuthTime() {
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertNotNull(result.getAuthTime());
    }

    @Test
    public void validatateIssuedAtIsSmallerThanExpiredAt() {
        Claims result = endpoint.checkToken(accessToken.getValue());
        Integer iat = result.getIat();
        assertNotNull(iat);
        Integer exp = result.getExp();
        assertNotNull(exp);
        assertTrue(iat<exp);
    }

    @Test
    public void testEmailInResult() {
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertEquals("olds@vmware.com", result.getEmail());
    }

    @Test
    public void testClientIdInResult() {
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertEquals("client", result.getClientId());
    }

    @Test
    public void testClientIdInAud() {
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertTrue(result.getAud().contains("client"));
    }


    @Test
    public void testExpiryResult() {
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertTrue(expiresIn + System.currentTimeMillis() / 1000 >= result.getExp());
    }

    @Test
    public void testUserAuthoritiesNotInResult() {
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertEquals(null, result.getAuthorities());
    }

    @Test
    public void testClientAuthoritiesNotInResult() {
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertEquals(null, result.getAuthorities());
    }

    @Test(expected = InvalidTokenException.class)
    public void testExpiredToken() throws Exception {
        BaseClientDetails clientDetails = new BaseClientDetails("client", "scim, cc", "read, write",
                        "authorization_code, password", "scim.read, scim.write", "http://localhost:8080/uaa");
        clientDetails.setAccessTokenValiditySeconds(1);
        Map<String, ? extends ClientDetails> clientDetailsStore = Collections.singletonMap("client", clientDetails);
        clientDetailsService.setClientDetailsStore(clientDetailsStore);
        tokenServices.setClientDetailsService(clientDetailsService);
        accessToken = tokenServices.createAccessToken(authentication);
        Thread.sleep(1000);
        Claims result = endpoint.checkToken(accessToken.getValue());
    }

    @Test(expected = InvalidTokenException.class)
    public void testUpdatedApprovals() {
        Date thirtySecondsAhead = new Date(System.currentTimeMillis() + 30000);
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId("client")
            .setScope("read")
            .setExpiresAt(thirtySecondsAhead)
            .setStatus(ApprovalStatus.APPROVED));
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertEquals(null, result.getAuthorities());
    }

    @Test(expected = InvalidTokenException.class)
    public void testDeniedApprovals() {
        Date oneSecondAgo = new Date(System.currentTimeMillis() - 1000);
        Date thirtySecondsAhead = new Date(System.currentTimeMillis() + 30000);
        approvalStore.revokeApproval(new Approval()
            .setUserId(userId)
            .setClientId("client")
            .setScope("read")
            .setExpiresAt(thirtySecondsAhead)
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(oneSecondAgo));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId("client")
            .setScope("read")
            .setExpiresAt(thirtySecondsAhead)
            .setStatus(ApprovalStatus.DENIED)
            .setLastUpdatedAt(oneSecondAgo));
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertEquals(null, result.getAuthorities());
    }

    @Test(expected = InvalidTokenException.class)
    public void testExpiredApprovals() {
        approvalStore.revokeApproval(new Approval()
            .setUserId(userId)
            .setClientId("client")
            .setScope("read")
            .setExpiresAt(new Date())
            .setStatus(ApprovalStatus.APPROVED));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId("client")
            .setScope("read")
            .setExpiresAt(new Date())
            .setStatus(ApprovalStatus.APPROVED));
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertEquals(null, result.getAuthorities());
    }

    @Test
    public void testClientOnly() {
        authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                        Collections.singleton("scim.read")).createOAuth2Request(), null);
        accessToken = tokenServices.createAccessToken(authentication);
        Claims result = endpoint.checkToken(accessToken.getValue());
        assertEquals("client", result.getClientId());
        assertEquals("client", result.getUserId());
    }

}
