/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.approval.ApprovalService;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.approval.InMemoryApprovalStore;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.AbstractOAuth2AccessTokenMatchers;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventPublisher;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.InMemoryClientServicesExtentions;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.mockito.stubbing.Answer;
import org.opensaml.saml2.core.AuthnContext;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.singleton;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.user.UaaAuthority.USER_AUTHORITIES;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TokenTestSupport {
    public static final String CLIENT_ID = "client";
    public static final String CLIENT_ID_NO_REFRESH_TOKEN_GRANT = "client_without_refresh_grant";
    public static final String GRANT_TYPE = "grant_type";
    public static final String CLIENT_AUTHORITIES = "read,update,write,openid";
    public static final String ISSUER_URI = "http://localhost:8080/uaa/oauth/token";
    public static final String READ = "read";
    public static final String WRITE = "write";
    public static final String DELETE = "delete";
    public static final String ALL_GRANTS_CSV = "authorization_code,password,implicit,client_credentials,refresh_token";
    public static final String CLIENTS = "clients";
    public static final String SCIM = "scim";
    public static final String OPENID = "openid";
    public static final String ROLES = "roles";
    public static final String PROFILE = "profile";
    public static final String DEFAULT_ISSUER = "http://localhost:8080/uaa";

    String userId = "12345";
    String username = "jdsa";
    String email = "jdsa@vmware.com";
    final String externalId = "externalId";

    List<? extends GrantedAuthority> defaultUserAuthorities = Arrays.asList(
        UaaAuthority.authority("space.123.developer"),
        UaaAuthority.authority("uaa.user"),
        UaaAuthority.authority("space.345.developer"),
        UaaAuthority.authority("space.123.admin"),
        UaaAuthority.authority(OPENID),
        UaaAuthority.authority(READ),
        UaaAuthority.authority(WRITE),
        UaaAuthority.authority("uaa.offline_token"));

    UaaUser defaultUser  =
        new UaaUser(
            new UaaUserPrototype()
                .withId(userId)
                .withUsername(username)
                .withPassword(GRANT_TYPE_PASSWORD)
                .withEmail(email)
                .withAuthorities(defaultUserAuthorities)
                .withGivenName("Marissa")
                .withFamilyName("Bloggs")
                .withPhoneNumber("1234567890")
                .withCreated(new Date(System.currentTimeMillis() - 15000))
                .withModified(new Date(System.currentTimeMillis() - 15000))
                .withOrigin(OriginKeys.UAA)
                .withExternalId(externalId)
                .withVerified(false)
                .withZoneId(IdentityZoneHolder.get().getId())
                .withSalt(userId)
                .withPasswordLastModified(new Date(System.currentTimeMillis() - 15000))
                .withLastLogonSuccess(12345L)
                .withPreviousLogonSuccess(12365L)
        );

    UaaTokenServices tokenServices;

    final int accessTokenValidity = 60 * 60 * 12;
    final int refreshTokenValidity = 60 * 60 * 24 * 30;

    TestApplicationEventPublisher<TokenIssuedEvent> publisher;

    // Need to create a user with a modified time slightly in the past because
    // the token IAT is in seconds and the token
    // expiry
    // skew will not be long enough
    InMemoryUaaUserDatabase userDatabase;

    Authentication defaultUserAuthentication;

    InMemoryClientServicesExtentions clientDetailsService = new InMemoryClientServicesExtentions();

    ApprovalStore approvalStore = new InMemoryApprovalStore();
    ApprovalService approvalService;
    MockAuthentication mockAuthentication;
    List<String> requestedAuthScopes;
    List<String> clientScopes;
    List<String> readScope;
    List<String> writeScope;
    List<String> expandedScopes;
    List<String> resourceIds;
    String expectedJson;
    BaseClientDetails defaultClient;
    BaseClientDetails clientWithoutRefreshToken;
    OAuth2RequestFactory requestFactory;
    TokenPolicy tokenPolicy;
    RevocableTokenProvisioning tokenProvisioning;
    final Map<String, RevocableToken> tokens = new HashMap<>();
    private final RefreshTokenCreator refreshTokenCreator;
    public final TimeService timeService;
    public final TokenValidationService tokenValidationService;
    private KeyInfoService keyInfoService;

    public void clear() {
        tokens.clear();
        AbstractOAuth2AccessTokenMatchers.revocableTokens.remove();
    }

    public TokenTestSupport(UaaTokenEnhancer tokenEnhancer) throws Exception {
        tokens.clear();
        publisher = TestApplicationEventPublisher.forEventClass(TokenIssuedEvent.class);
        IdentityZoneHolder.clear();
        IdentityZoneProvisioning provisioning = mock(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(provisioning);
        IdentityZone zone = IdentityZone.getUaa();
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        tokenPolicy = new TokenPolicy(accessTokenValidity, refreshTokenValidity);
        Map<String, String> keys = new HashMap<>();
        keys.put("testKey", "9c247h8yt978w3nv45y978w45hntv6");
        keys.put("otherKey", "unc0uf98gv89egh4v98749978hv");
        tokenPolicy.setKeys(keys);
        tokenPolicy.setActiveKeyId("testKey");
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        when(provisioning.retrieve("uaa")).thenReturn(zone);

        userDatabase = new InMemoryUaaUserDatabase(singleton(defaultUser));
        defaultUserAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(defaultUser), "n/a", null);

        mockAuthentication = new MockAuthentication();
        SecurityContextHolder.getContext().setAuthentication(mockAuthentication);
        requestedAuthScopes = Arrays.asList(READ, WRITE,OPENID);
        clientScopes = Arrays.asList(READ, WRITE,OPENID);
        readScope = Arrays.asList(READ);
        writeScope = Arrays.asList(WRITE);
        expandedScopes = Arrays.asList(READ, WRITE, DELETE,OPENID);
        resourceIds = Arrays.asList(SCIM, CLIENTS);
        expectedJson = "[\""+READ+"\",\""+WRITE+"\",\""+OPENID+"\"]";


        defaultClient = new BaseClientDetails(
            CLIENT_ID,
            SCIM+","+CLIENTS,
            READ+","+WRITE+","+OPENID+",uaa.offline_token",
            ALL_GRANTS_CSV,
            CLIENT_AUTHORITIES);

        clientWithoutRefreshToken = new BaseClientDetails(
            CLIENT_ID_NO_REFRESH_TOKEN_GRANT,
            SCIM+","+CLIENTS,
            READ+","+WRITE+","+OPENID+",uaa.offline_token",
                GRANT_TYPE_AUTHORIZATION_CODE,
            CLIENT_AUTHORITIES);

        Map<String, BaseClientDetails> clientDetailsMap = new HashMap<>();
        clientDetailsMap.put(CLIENT_ID, defaultClient);
        clientDetailsMap.put(CLIENT_ID_NO_REFRESH_TOKEN_GRANT, clientWithoutRefreshToken);

        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), clientDetailsMap);

        tokenProvisioning = mock(RevocableTokenProvisioning.class);
        when(tokenProvisioning.create(any(), anyString())).thenAnswer((Answer<RevocableToken>) invocation -> {
            RevocableToken arg = (RevocableToken)invocation.getArguments()[0];
            tokens.put(arg.getTokenId(), arg);
            return arg;
        });
        when(tokenProvisioning.update(anyString(), any(), anyString())).thenAnswer((Answer<RevocableToken>) invocation -> {
            String id = (String)invocation.getArguments()[0];
            RevocableToken arg = (RevocableToken)invocation.getArguments()[1];
            arg.setTokenId(id);
            tokens.put(arg.getTokenId(), arg);
            return arg;
        });
        when(tokenProvisioning.retrieve(anyString(), anyString())).thenAnswer((Answer<RevocableToken>) invocation -> {
            String id = (String)invocation.getArguments()[0];
            RevocableToken result = tokens.get(id);
            if (result==null) {
                throw new EmptyResultDataAccessException(1);
            }
            return result;

        });

        AbstractOAuth2AccessTokenMatchers.revocableTokens.set(tokens);

        requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
        timeService = mock(TimeService.class);
        approvalService = new ApprovalService(timeService, approvalStore);
        when(timeService.getCurrentDate()).thenCallRealMethod();
        TokenEndpointBuilder tokenEndpointBuilder = new TokenEndpointBuilder(DEFAULT_ISSUER);
        keyInfoService = new KeyInfoService(DEFAULT_ISSUER);
        tokenValidationService = new TokenValidationService(tokenProvisioning, tokenEndpointBuilder, userDatabase, clientDetailsService, keyInfoService);
        TokenValidityResolver refreshTokenValidityResolver = new TokenValidityResolver(new ClientRefreshTokenValidity(clientDetailsService), 12345, timeService);
        TokenValidityResolver accessTokenValidityResolver = new TokenValidityResolver(new ClientAccessTokenValidity(clientDetailsService), 1234, timeService);
        IdTokenCreator idTokenCreator = new IdTokenCreator(tokenEndpointBuilder, timeService, accessTokenValidityResolver, userDatabase, clientDetailsService, new HashSet<>());
        refreshTokenCreator = new RefreshTokenCreator(false, refreshTokenValidityResolver, tokenEndpointBuilder, timeService, keyInfoService);
        tokenServices = new UaaTokenServices(
                idTokenCreator,
                tokenEndpointBuilder,
                clientDetailsService,
                tokenProvisioning,
                tokenValidationService,
                refreshTokenCreator,
                timeService,
                accessTokenValidityResolver,
                userDatabase,
                Sets.newHashSet(),
                tokenPolicy,
                keyInfoService,
                new IdTokenGranter(approvalService),
                approvalService);

        tokenServices.setApplicationEventPublisher(publisher);
        tokenServices.setUaaTokenEnhancer(tokenEnhancer);

        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(
            new LinkedList<>(AuthorityUtils.authorityListToSet(USER_AUTHORITIES))
        );
    }

    public UaaTokenServices getUaaTokenServices() {
        return tokenServices;
    }

    public RevocableTokenProvisioning getTokenProvisioning() {
        return tokenProvisioning;
    }

    public CompositeToken getCompositeAccessToken(List<String> scopes) {
        UaaPrincipal uaaPrincipal = new UaaPrincipal(defaultUser.getId(), defaultUser.getUsername(), defaultUser.getEmail(), defaultUser.getOrigin(), defaultUser.getExternalId(), defaultUser.getZoneId());
        UaaAuthentication userAuthentication = new UaaAuthentication(uaaPrincipal, null, defaultUserAuthorities, new HashSet<>(Arrays.asList("group1", "group2")), Collections.EMPTY_MAP, null, true, System.currentTimeMillis(), System.currentTimeMillis() + 1000l * 60l);
        Set<String> amr = new HashSet<>();
        amr.addAll(Arrays.asList("ext", "mfa", "rba"));
        userAuthentication.setAuthenticationMethods(amr);
        userAuthentication.setAuthContextClassRef(new HashSet<>(Arrays.asList(AuthnContext.PASSWORD_AUTHN_CTX)));

        HashMap<String, String> requestParams = Maps.newHashMap();
        requestParams.put("grant_type", GRANT_TYPE_PASSWORD);
        OAuth2Request oAuth2Request = new OAuth2Request(requestParams, CLIENT_ID, null, false, Sets.newHashSet(scopes), null, null, Sets.newHashSet("token", "id_token"), null);

        UaaOauth2Authentication uaaOauth2Authentication = new UaaOauth2Authentication(null, IdentityZoneHolder.get().getId(), oAuth2Request, userAuthentication);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(uaaOauth2Authentication);
        return (CompositeToken) accessToken;
    }

    public String getIdTokenAsString(List<String> scopes) {
        return getCompositeAccessToken(scopes).getIdTokenValue();
    }

    public Jwt getIdToken(List<String> scopes) {
        CompositeToken accessToken = getCompositeAccessToken(scopes);
        Jwt tokenJwt = JwtHelper.decode(accessToken.getValue());
        SignatureVerifier verifier = keyInfoService.getKey(tokenJwt.getHeader().getKid()).getVerifier();
        tokenJwt.verifySignature(verifier);
        assertNotNull(tokenJwt);

        Jwt idToken = JwtHelper.decode(accessToken.getIdTokenValue());
        idToken.verifySignature(verifier);
        return idToken;
    }

    public InMemoryClientServicesExtentions getClientDetailsService() {
        return clientDetailsService;
    }

    public void copyClients(String fromZoneId, String toZoneId) {
        getClientDetailsService().setClientDetailsStore(toZoneId, getClientDetailsService().getInMemoryService(fromZoneId));
    }

}
