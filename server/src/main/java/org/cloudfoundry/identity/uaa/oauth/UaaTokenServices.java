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

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.approval.ApprovalService;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.openid.IdToken;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenCreationException;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.openid.UserAuthenticationData;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.ResourceServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.refresh.CompositeExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenRequestData;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.provider.oauth.TokenActor;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.UaaSecurityContextUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.util.Collections.emptyMap;
import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.openid.IdToken.ACR_VALUES_KEY;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.*;
import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_EMPTY;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_NONE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ISSUED_TOKEN_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_AUTHORITIES;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.SUBJECT_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ACCESS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.springframework.util.StringUtils.hasText;


/**
 * This class provides token services for the UAA. It handles the production and
 * consumption of UAA tokens.
 *
 */
@Component("tokenServices")
public class UaaTokenServices implements AuthorizationServerTokenServices, ResourceServerTokenServices, ApplicationEventPublisherAware {

    private static final Set<String> NON_ADDITIONAL_ROOT_CLAIMS = Set.of(
            JTI, SUB, AUTHORITIES, OAuth2AccessToken.SCOPE,
            CLIENT_ID, CID, AZP, REVOCABLE,
            GRANT_TYPE, USER_ID, ORIGIN, USER_NAME,
            EMAIL, AUTH_TIME, REVOCATION_SIGNATURE, IAT,
            EXPIRY_IN_SECONDS, ISS, ZONE_ID, AUD
    );
    private static final long MILLIS_PER_SECOND = 1000L;
    private final Logger logger = LoggerFactory.getLogger(UaaTokenServices.class);
    private final UaaUserDatabase userDatabase;
    private MultitenantClientServices clientDetailsService;
    private final ApprovalService approvalService;
    private ApplicationEventPublisher applicationEventPublisher;
    private final TokenPolicy tokenPolicy;
    private final RevocableTokenProvisioning tokenProvisioning;
    private Set<String> excludedClaims;
    private UaaTokenEnhancer uaaTokenEnhancer;
    private final IdTokenCreator idTokenCreator;
    private final RefreshTokenCreator refreshTokenCreator;
    private TokenEndpointBuilder tokenEndpointBuilder;
    private TimeService timeService;
    private final TokenValidityResolver accessTokenValidityResolver;
    private final TokenValidationService tokenValidationService;
    private final KeyInfoService keyInfoService;
    private final IdTokenGranter idTokenGranter;

    public UaaTokenServices(IdTokenCreator idTokenCreator,
            TokenEndpointBuilder tokenEndpointBuilder,
            MultitenantClientServices clientDetailsService,
            RevocableTokenProvisioning revocableTokenProvisioning,
            TokenValidationService tokenValidationService,
            RefreshTokenCreator refreshTokenCreator,
            TimeService timeService,
            TokenValidityResolver accessTokenValidityResolver,
            UaaUserDatabase userDatabase,
            Set<String> excludedClaims,
            TokenPolicy globalTokenPolicy,
            KeyInfoService keyInfoService,
            IdTokenGranter idTokenGranter,
            ApprovalService approvalService) {
        this.idTokenCreator = idTokenCreator;
        this.tokenEndpointBuilder = tokenEndpointBuilder;
        this.clientDetailsService = clientDetailsService;
        this.tokenProvisioning = revocableTokenProvisioning;
        this.tokenValidationService = tokenValidationService;
        this.refreshTokenCreator = refreshTokenCreator;
        this.timeService = timeService;
        this.accessTokenValidityResolver = accessTokenValidityResolver;
        this.userDatabase = userDatabase;
        this.approvalService = approvalService;
        this.excludedClaims = new HashSet<>(excludedClaims);
        this.tokenPolicy = globalTokenPolicy;
        this.idTokenGranter = idTokenGranter;
        this.keyInfoService = keyInfoService;
    }

    public Set<String> getExcludedClaims() {
        return new HashSet<>(excludedClaims);
    }

    public void setExcludedClaims(Set<String> excludedClaims) {
        this.excludedClaims = new HashSet<>(excludedClaims);
    }

    public void setUaaTokenEnhancer(UaaTokenEnhancer uaaTokenEnhancer) {
        this.uaaTokenEnhancer = uaaTokenEnhancer;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    @Override
    public OAuth2AccessToken refreshAccessToken(String refreshTokenValue, TokenRequest request) throws AuthenticationException {
        if (null == refreshTokenValue) {
            throw new InvalidTokenException("Invalid refresh token (empty token)");
        }

        JwtTokenSignedByThisUAA jwtToken = tokenValidationService
                .validateToken(refreshTokenValue, false)
                .checkJti();
        Map<String, Object> refreshTokenClaims = jwtToken.getClaims();

        ArrayList<String> tokenScopes = getScopesFromRefreshToken(refreshTokenClaims);
        refreshTokenCreator.ensureRefreshTokenCreationNotRestricted(tokenScopes);

        Claims claims = getClaims(refreshTokenClaims);

        // default request scopes to what is in the refresh token
        Set<String> requestedScopes = request.getScope().isEmpty() ? Sets.newHashSet(tokenScopes) : request.getScope();
        Map<String, String> requestParams = request.getRequestParameters();
        String requestedTokenFormat = requestParams.get(REQUEST_TOKEN_FORMAT);
        String requestedClientId = request.getClientId();

        if (claims.getCid() == null || !claims.getCid().equals(requestedClientId)) {
            throw new InvalidGrantException("Wrong client for this refresh token: " + claims.getCid());
        }
        boolean isOpaque = OPAQUE.getStringValue().equals(requestedTokenFormat);
        boolean isRevocable = isRevocable(claims, isOpaque);

        UaaUser user = new UaaUser(userDatabase.retrieveUserPrototypeById(claims.getUserId()));
        UaaClientDetails client = (UaaClientDetails) clientDetailsService.loadClientByClientId(claims.getCid());

        long refreshTokenExpireMillis = claims.getExp().longValue() * MILLIS_PER_SECOND;
        if (new Date(refreshTokenExpireMillis).before(timeService.getCurrentDate())) {
            throw new InvalidTokenException("Invalid refresh token expired at " + new Date(refreshTokenExpireMillis));
        }

        // The user may not request scopes that were not part of the refresh token
        if (tokenScopes.isEmpty() || !tokenScopes.containsAll(requestedScopes)) {
            throw new InvalidScopeException(
                    "Unable to narrow the scope of the client authentication to " + requestedScopes + ".",
                    new HashSet<>(tokenScopes)
            );
        }

        // ensure all requested scopes are approved: either automatically or
        // explicitly by the user
        approvalService.ensureRequiredApprovals(
                claims.getUserId(),
                requestedScopes,
                claims.getGrantType(),
                client);

        throwIfInvalidRevocationHashSignature(claims.getRevSig(), user, client);

        Map<String, Object> additionalRootClaims = getAdditionalRootClaims(refreshTokenClaims);

        UserAuthenticationData authenticationData = new UserAuthenticationData(
                AuthTimeDateConverter.authTimeToDate(claims.getAuthTime()),
                authenticationMethodsAsSet(refreshTokenClaims),
                getAcrAsSet(refreshTokenClaims),
                requestedScopes,
                rolesAsSet(claims.getUserId()),
                getUserAttributes(claims.getUserId()),
                claims.getNonce(),
                claims.getGrantType(),
                UaaSecurityContextUtils.getClientAuthenticationMethod(),
                generateUniqueTokenId()
        );

        addAuthenticationMethod(claims, additionalRootClaims, authenticationData);

        String accessTokenId = generateUniqueTokenId();
        String clientAuth = authenticationData.clientAuth;
        refreshTokenValue = refreshTokenCreator.createRefreshTokenValue(jwtToken, claims, clientAuth);
        CompositeToken compositeToken =
                createCompositeToken(
                        accessTokenId,
                        user,
                        AuthTimeDateConverter.authTimeToDate(claims.getAuthTime()),
                        getClientPermissions(client),
                        claims.getCid(),
                        Set.copyOf(claims.getAud()),
                        refreshTokenValue,
                        claims.getAzAttr(),
                        additionalRootClaims,
                        claims.getRevSig(),
                        isRevocable,
                        authenticationData
                );

        CompositeExpiringOAuth2RefreshToken expiringRefreshToken = new CompositeExpiringOAuth2RefreshToken(
                refreshTokenValue, new Date(refreshTokenExpireMillis), claims.getJti()
        );

        String tokenIdToBeDeleted = null;
        if (isRevocable && refreshTokenCreator.shouldRotateRefreshTokens(clientAuth)) {
            tokenIdToBeDeleted = (String) jwtToken.getClaims().get(JTI);
        }
        return persistRevocableToken(accessTokenId, compositeToken, expiringRefreshToken, claims.getClientId(), user.getId(), isOpaque, isRevocable, tokenIdToBeDeleted);
    }

    private static String getAuthenticationMethod(OAuth2Request oAuth2Request) {
        return ofNullable(oAuth2Request.getExtensions().get(CLIENT_AUTH_METHOD)).map(String.class::cast).orElse(null);
    }

    private void addAuthenticationMethod(Claims claims, Map<String, Object> additionalRootClaims, UserAuthenticationData authenticationData) {
        if (authenticationData.clientAuth != null) {
            // public refresh flow, allowed if access_token before was also without authentication (claim: client_auth_method=none) and refresh token is one time use (rotate it in refresh)
            if (CLIENT_AUTH_NONE.equals(authenticationData.clientAuth) && // current authentication
                    (!CLIENT_AUTH_NONE.equals(claims.getClientAuth()) || // authentication before
                            !refreshTokenCreator.shouldRotateRefreshTokens(authenticationData.clientAuth))) {
                throw new TokenRevokedException("Refresh without client authentication not allowed.");
            }
            addRootClaimEntry(additionalRootClaims, CLIENT_AUTH_METHOD, authenticationData.clientAuth);
        }
    }

    private Map<String, Object> addTokenExchangeClaims(Map<String, Object> additionalRootClaims, OAuth2Request oAuth2Request) {
        String subjectToken = oAuth2Request.getRequestParameters().get(SUBJECT_TOKEN);
        if (!hasText(subjectToken) || oAuth2Request.getTokenActor() == null) {
            return additionalRootClaims;
        }
        if (additionalRootClaims == null) {
            additionalRootClaims = new HashMap<>();
        }
        additionalRootClaims.put(ACT, oAuth2Request.getTokenActor().getClaims());
        return additionalRootClaims;
    }

    private static Map<String, Object> addAuthenticationMethod(Map<String, Object> additionalRootClaims, String clientAuthentication) {
        if (clientAuthentication != null) {
            additionalRootClaims = addRootClaimEntry(additionalRootClaims, CLIENT_AUTH_METHOD, clientAuthentication);
        }
        return additionalRootClaims;
    }

    Claims getClaims(Map<String, Object> refreshTokenClaims) {
        try {
            return JsonUtils.convertValue(refreshTokenClaims, Claims.class);
        } catch (JsonUtils.JsonUtilException e) {
            logger.error("Cannot read token claims", e);
            throw new InvalidTokenException("Cannot read token claims", e);
        }
    }

    private Map<String, Object> getAdditionalRootClaims(Map<String, Object> refreshTokenClaims) {
        Map<String, Object> additionalRootClaims = new HashMap<>();
        if (uaaTokenEnhancer != null) {
            refreshTokenClaims.entrySet()
                    .stream()
                    .filter(entry -> !NON_ADDITIONAL_ROOT_CLAIMS.contains(entry.getKey()))
                    .forEach(
                            entry -> additionalRootClaims.put(entry.getKey(), entry.getValue())
                    );
            // `granted_scopes` claim should not be present in an access token
            refreshTokenClaims.remove(GRANTED_SCOPES);
        }
        return additionalRootClaims;
    }

    static boolean isRevocable(Claims claims, boolean isOpaque) {
        return isOpaque || claims.isRevocable();
    }

    private static void throwIfInvalidRevocationHashSignature(String revocableHashSignature, UaaUser user, ClientDetails client) {
        if (hasText(revocableHashSignature)) {
            String clientSecretForHash = getClientSecretForHash(client.getClientSecret());
            String newRevocableHashSignature = UaaTokenUtils.getRevocableTokenSignature(client, clientSecretForHash, user);
            if (!revocableHashSignature.equals(newRevocableHashSignature)) {
                throw new TokenRevokedException("Invalid refresh token: revocable signature mismatch");
            }
        }
    }

    private static Set<String> getAcrAsSet(Map<String, Object> refreshTokenClaims) {

        Map<String, Object> acrFromRefreshToken = (Map<String, Object>) refreshTokenClaims.get(ACR);
        if (acrFromRefreshToken == null) {
            return null;
        }

        return new HashSet<>((Collection<String>) acrFromRefreshToken.get(ACR_VALUES_KEY));
    }

    private MultiValueMap<String, String> getUserAttributes(String userId) {
        UserInfo userInfo = userDatabase.getUserInfo(userId);
        if (userInfo != null) {
            return userInfo.getUserAttributes();
        } else {
            return new LinkedMultiValueMap<>();
        }
    }


    private HashSet<String> rolesAsSet(String userId) {
        UserInfo userInfo = userDatabase.getUserInfo(userId);
        if (userInfo != null) {
            ArrayList<String> roles = (ArrayList<String>) userInfo.getRoles();
            return roles == null ? Sets.newHashSet() : Sets.newHashSet(roles);
        } else {
            return Sets.newHashSet();
        }
    }

    private static HashSet<String> authenticationMethodsAsSet(Map<String, Object> refreshTokenClaims) {
        ArrayList<String> authenticationMethods = (ArrayList<String>) refreshTokenClaims.get(AMR);
        return authenticationMethods == null ? Sets.newHashSet() : Sets.newHashSet(authenticationMethods);
    }

    private CompositeToken createCompositeToken(String tokenId,
            UaaUser user,
            Date userAuthenticationTime,
            Collection<GrantedAuthority> clientScopes,
            String clientId,
            Set<String> resourceIds,
            String refreshToken,
            Map<String, String> additionalAuthorizationAttributes,
            Map<String, Object> additionalRootClaims,
            String revocableHashSignature,
            boolean isRevocable,
            UserAuthenticationData userAuthenticationData) throws AuthenticationException {
        CompositeToken compositeToken = new CompositeToken(tokenId);
        compositeToken.setExpiration(accessTokenValidityResolver.resolve(clientId));
        compositeToken.setRefreshToken(refreshToken == null ? null : new DefaultOAuth2RefreshToken(refreshToken));

        Set<String> requestedScopes = userAuthenticationData.scopes;
        String grantType = userAuthenticationData.grantType;

        if (null == requestedScopes || requestedScopes.isEmpty()) {
            logger.debug("No scopes were granted");
            throw new InvalidTokenException("No scopes were granted");
        }

        compositeToken.setScope(requestedScopes);

        ConcurrentMap<String, Object> info = new ConcurrentHashMap<>();
        info.put(JTI, compositeToken.getValue());
        if (null != additionalAuthorizationAttributes) {
            info.put(ADDITIONAL_AZ_ATTR, additionalAuthorizationAttributes);
        }

        String nonce = userAuthenticationData.nonce;
        if (nonce != null) {
            info.put(NONCE, nonce);
        }

        TokenActor tokenActor = null;
        if (GRANT_TYPE_TOKEN_EXCHANGE.equals(userAuthenticationData.grantType)) {
            info.put(ISSUED_TOKEN_TYPE, TOKEN_TYPE_ACCESS);
            if (additionalRootClaims != null) {
                tokenActor = new TokenActor((Map<String, Object>) additionalRootClaims.get(ACT));
            }
        }

        compositeToken.setAdditionalInformation(info);

        Map<String, Object> jwtAccessToken = createJWTAccessToken(
                compositeToken,
                user,
                userAuthenticationTime,
                clientScopes,
                requestedScopes,
                clientId,
                resourceIds,
                grantType,
                revocableHashSignature,
                isRevocable,
                additionalRootClaims);
        String token = JwtHelper.encode(jwtAccessToken, getActiveKeyInfo()).getEncoded();
        compositeToken.setValue(token);
        UaaClientDetails clientDetails = (UaaClientDetails) clientDetailsService.loadClientByClientId(clientId);

        if (idTokenGranter.shouldSendIdToken(user, clientDetails, requestedScopes, grantType)) {
            IdToken idTokenContent;
            try {
                idTokenContent = idTokenCreator.create(clientDetails, user, userAuthenticationData, tokenActor);
            } catch (RuntimeException | IdTokenCreationException ignored) {
                throw new IllegalStateException("Cannot convert id token to JSON");
            }
            String encodedIdTokenContent = JwtHelper.encode(idTokenContent.getClaimMap(), keyInfoService.getActiveKey()).getEncoded();
            compositeToken.setIdTokenValue(encodedIdTokenContent);
        }

        publish(new TokenIssuedEvent(compositeToken, SecurityContextHolder.getContext().getAuthentication(), IdentityZoneHolder.getCurrentZoneId()));

        return compositeToken;
    }

    private static Map<String, Object> addRootClaimEntry(Map<String, Object> additionalRootClaims, String entry, String value) {
        Map<String, Object> claims = additionalRootClaims != null ? additionalRootClaims : new HashMap<>();
        // set externally none as client_auth_method if internally empty
        claims.put(entry, CLIENT_AUTH_EMPTY.equals(value) ? CLIENT_AUTH_NONE : value);
        return claims;
    }

    private KeyInfo getActiveKeyInfo() {
        return ofNullable(keyInfoService.getActiveKey())
                .orElseThrow(() -> new InternalAuthenticationServiceException("Unable to sign token, misconfigured JWT signing keys"));
    }

    private Map<String, Object> createJWTAccessToken(OAuth2AccessToken token,
            UaaUser user,
            Date userAuthenticationTime,
            Collection<GrantedAuthority> clientScopes,
            Set<String> requestedScopes,
            String clientId,
            Set<String> resourceIds,
            String grantType,
            String revocableHashSignature,
            boolean isRevocable,
            Map<String, Object> additionalRootClaims) {

        Map<String, Object> claims = new LinkedHashMap<>();

        claims.put(JTI, token.getAdditionalInformation().get(JTI));
        claims.putAll(token.getAdditionalInformation());

        if (additionalRootClaims != null) {
            claims.putAll(additionalRootClaims);
        }

        claims.put(SUB, clientId);
        if (GRANT_TYPE_CLIENT_CREDENTIALS.equals(grantType)) {
            claims.put(AUTHORITIES, AuthorityUtils.authorityListToSet(clientScopes));
        }

        claims.put(OAuth2AccessToken.SCOPE, requestedScopes);
        putClientIntoJWT(clientId, claims);
        if (isRevocable) {
            claims.put(REVOCABLE, true);
        }

        if (null != grantType) {
            claims.put(GRANT_TYPE, grantType);
        }
        putUserIntoJWT(user, userAuthenticationTime, claims);

        if (StringUtils.hasText(revocableHashSignature)) {
            claims.put(REVOCATION_SIGNATURE, revocableHashSignature);
        }

        claims.put(IAT, timeService.getCurrentTimeMillis() / MILLIS_PER_SECOND);
        claims.put(EXPIRY_IN_SECONDS, token.getExpiration().getTime() / MILLIS_PER_SECOND);

        if (tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()) != null) {
            claims.put(ISS, tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
            claims.put(ZONE_ID, IdentityZoneHolder.get().getId());
        }

        claims.put(AUD, UaaStringUtils.getValuesOrDefaultValue(resourceIds, clientId));

        for (String excludedClaim : getExcludedClaims()) {
            claims.remove(excludedClaim);
        }

        return claims;
    }

    private static void putClientIntoJWT(String clientId, Map<String, Object> claims) {
        claims.put(CLIENT_ID, clientId);
        claims.put(CID, clientId);
        claims.put(AZP, clientId);
    }

    private static void putUserIntoJWT(UaaUser user, Date userAuthenticationTime, Map<String, Object> claims) {
        if (user != null) {
            claims.put(USER_ID, user.getId());
            String origin = user.getOrigin();
            if (StringUtils.hasLength(origin)) {
                claims.put(ORIGIN, origin);
            }
            String username = user.getUsername();
            claims.put(USER_NAME, username == null ? user.getId() : username);
            String userEmail = user.getEmail();
            if (userEmail != null) {
                claims.put(EMAIL, userEmail);
            }
            if (userAuthenticationTime != null) {
                claims.put(AUTH_TIME, userAuthenticationTime.getTime() / MILLIS_PER_SECOND);
            }
            claims.put(SUB, user.getId());
        }
    }

    @Override
    public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
        String userId = null;
        Date userAuthenticationTime = null;
        UaaUser user = null;

        Set<String> authenticationMethods = null;
        Set<String> authNContextClassRef = null;

        OAuth2Request oAuth2Request = authentication.getOAuth2Request();
        UaaClientDetails client = (UaaClientDetails) clientDetailsService.loadClientByClientId(oAuth2Request.getClientId(), IdentityZoneHolder.get().getId());
        Collection<GrantedAuthority> clientScopes = null;

        // Clients should really by different kinds of users
        if (authentication.isClientOnly()) {
            clientScopes = client.getAuthorities();
        } else {
            clientScopes = getClientPermissions(client);
            userId = getUserId(authentication);
            user = userDatabase.retrieveUserById(userId);
            if (authentication.getUserAuthentication() instanceof UaaAuthentication) {
                userAuthenticationTime = new Date(((UaaAuthentication) authentication.getUserAuthentication()).getAuthenticatedTime());
                authenticationMethods = ((UaaAuthentication) authentication.getUserAuthentication()).getAuthenticationMethods();
                authNContextClassRef = ((UaaAuthentication) authentication.getUserAuthentication()).getAuthContextClassRef();
            }
            validateRequiredUserGroups(user, client);
        }


        String clientSecretForHash = getClientSecretForHash(client.getClientSecret());
        String revocableHashSignature = UaaTokenUtils.getRevocableTokenSignature(client, clientSecretForHash, user);

        String tokenId = generateUniqueTokenId();

        boolean isOpaque = isOpaqueTokenRequired(authentication);
        boolean isAccessTokenRevocable = isOpaque || getActiveTokenPolicy().isJwtRevocable();
        boolean isRefreshTokenRevocable = isAccessTokenRevocable || OPAQUE.getStringValue().equals(getActiveTokenPolicy().getRefreshTokenFormat());

        Map<String, Object> additionalRootClaims = null;
        if (uaaTokenEnhancer != null) {
            additionalRootClaims = new HashMap<>(uaaTokenEnhancer.enhance(emptyMap(), authentication));
        }

        String clientAuthentication = getAuthenticationMethod(oAuth2Request);
        additionalRootClaims = addAuthenticationMethod(additionalRootClaims, clientAuthentication);

        if (GRANT_TYPE_TOKEN_EXCHANGE.equals(oAuth2Request.getGrantType())) {
            additionalRootClaims = addTokenExchangeClaims(additionalRootClaims, oAuth2Request);
        }

        CompositeExpiringOAuth2RefreshToken refreshToken = null;
        if (client.getAuthorizedGrantTypes().contains(GRANT_TYPE_REFRESH_TOKEN)) {
            RefreshTokenRequestData refreshTokenRequestData = new RefreshTokenRequestData(
                    oAuth2Request.getGrantType(),
                    oAuth2Request.getScope(),
                    authenticationMethods,
                    oAuth2Request.getRequestParameters().get(REQUEST_AUTHORITIES),
                    oAuth2Request.getResourceIds(),
                    oAuth2Request.getClientId(),
                    isRefreshTokenRevocable,
                    userAuthenticationTime,
                    authNContextClassRef,
                    additionalRootClaims
            );
            refreshToken = refreshTokenCreator.createRefreshToken(user, refreshTokenRequestData, revocableHashSignature);
        }

        String clientId = oAuth2Request.getClientId();
        Set<String> userScopes = oAuth2Request.getScope();
        Map<String, String> requestParameters = oAuth2Request.getRequestParameters();
        String grantType = requestParameters.get(GRANT_TYPE);

        Set<String> modifiableUserScopes = new LinkedHashSet<>(userScopes);

        Map<String, List<String>> userAttributesForIdToken = Maps.newHashMap();
        if (authentication.getUserAuthentication() instanceof UaaAuthentication) {
            userAttributesForIdToken = ((UaaAuthentication) authentication.getUserAuthentication()).getUserAttributes();
        }

        String nonce = requestParameters.get(NONCE);

        Map<String, String> additionalAuthorizationAttributes =
                new AuthorizationAttributesParser().getAdditionalAuthorizationAttributes(
                        requestParameters.get(REQUEST_AUTHORITIES)
                );

        UserAuthenticationData authenticationData = new UserAuthenticationData(userAuthenticationTime,
                authenticationMethods,
                authNContextClassRef,
                modifiableUserScopes,
                rolesAsSet(userId),
                userAttributesForIdToken,
                nonce,
                grantType,
                clientAuthentication,
                tokenId
        );

        String refreshTokenValue = refreshToken != null ? refreshToken.getValue() : null;

        CompositeToken accessToken =
                createCompositeToken(
                        tokenId,
                        user,
                        userAuthenticationTime,
                        clientScopes,
                        clientId,
                        oAuth2Request.getResourceIds(),
                        refreshTokenValue,
                        additionalAuthorizationAttributes,
                        additionalRootClaims,
                        revocableHashSignature,
                        isAccessTokenRevocable,
                        authenticationData);

        return persistRevocableToken(tokenId, accessToken, refreshToken, clientId, userId, isOpaque, isAccessTokenRevocable, null);
    }

    private static String getClientSecretForHash(String clientSecret) {
        String clientSecretForHash = clientSecret;
        if (clientSecretForHash != null && clientSecretForHash.split(" ").length > 1) {
            clientSecretForHash = clientSecretForHash.split(" ")[1];
        }
        return clientSecretForHash;
    }

    private static TokenPolicy getActiveTokenPolicy() {
        return IdentityZoneHolder.get().getConfig().getTokenPolicy();
    }

    private static Collection<GrantedAuthority> getClientPermissions(ClientDetails client) {
        Collection<GrantedAuthority> clientScopes;
        clientScopes = new ArrayList<>();
        for (String scope : client.getScope()) {
            clientScopes.add(new SimpleGrantedAuthority(scope));
        }
        return clientScopes;
    }

    private static void validateRequiredUserGroups(UaaUser user, ClientDetails client) {
        Collection<String> requiredUserGroups = ofNullable((Collection<String>) client.getAdditionalInformation().get(REQUIRED_USER_GROUPS)).orElse(emptySet());
        if (!UaaTokenUtils.hasRequiredUserAuthorities(requiredUserGroups, user.getAuthorities())) {
            throw new InvalidTokenException("User does not meet the client's required group criteria.");
        }
    }

    CompositeToken persistRevocableToken(String tokenId,
            CompositeToken token,
            CompositeExpiringOAuth2RefreshToken refreshToken,
            String clientId,
            String userId,
            boolean isOpaque,
            boolean isRevocable,
            String tokenIdToBeDeleted) {

        String scope = token.getScope().toString();
        long now = timeService.getCurrentTimeMillis();
        if (isRevocable) {
            RevocableToken revocableAccessToken = new RevocableToken()
                    .setTokenId(tokenId)
                    .setClientId(clientId)
                    .setExpiresAt(token.getExpiration().getTime())
                    .setIssuedAt(now)
                    .setFormat(isOpaque ? OPAQUE.getStringValue() : JWT.getStringValue())
                    .setResponseType(ACCESS_TOKEN)
                    .setZoneId(IdentityZoneHolder.get().getId())
                    .setUserId(userId)
                    .setScope(scope)
                    .setValue(token.getValue());
            tokenProvisioning.upsert(tokenId, revocableAccessToken, IdentityZoneHolder.get().getId());
        }

        boolean isRefreshTokenOpaque = isOpaque || OPAQUE.getStringValue().equals(getActiveTokenPolicy().getRefreshTokenFormat());
        boolean refreshTokenRevocable = isRefreshTokenOpaque || getActiveTokenPolicy().isJwtRevocable();
        boolean refreshTokenUnique = getActiveTokenPolicy().isRefreshTokenUnique();
        if (refreshToken != null && refreshTokenRevocable) {
            RevocableToken revocableRefreshToken = new RevocableToken()
                    .setTokenId(refreshToken.getJti())
                    .setClientId(clientId)
                    .setExpiresAt(refreshToken.getExpiration().getTime())
                    .setIssuedAt(now)
                    .setFormat(isRefreshTokenOpaque ? OPAQUE.getStringValue() : JWT.getStringValue())
                    .setResponseType(REFRESH_TOKEN)
                    .setZoneId(IdentityZoneHolder.get().getId())
                    .setUserId(userId)
                    .setScope(scope)
                    .setValue(refreshToken.getValue());
            if (refreshTokenUnique) {
                tokenProvisioning.deleteRefreshTokensForClientAndUserId(clientId, userId, IdentityZoneHolder.get().getId());
            }
            tokenProvisioning.createIfNotExists(revocableRefreshToken, IdentityZoneHolder.get().getId());
            if (tokenIdToBeDeleted != null) {
                tokenProvisioning.delete(tokenIdToBeDeleted, -1, IdentityZoneHolder.getCurrentZoneId());
            }
        }

        CompositeToken result = new CompositeToken(isOpaque ? tokenId : token.getValue());
        result.setIdTokenValue(token.getIdTokenValue());
        result.setExpiration(token.getExpiration());
        result.setAdditionalInformation(token.getAdditionalInformation());
        result.setScope(token.getScope());
        result.setTokenType(token.getTokenType());
        result.setRefreshToken(buildRefreshTokenResponse(refreshToken, isRefreshTokenOpaque));
        return result;
    }

    private static OAuth2RefreshToken buildRefreshTokenResponse(CompositeExpiringOAuth2RefreshToken refreshToken, boolean isRefreshTokenOpaque) {
        if (refreshToken == null) {
            return null;
        } else {
            if (isRefreshTokenOpaque) {
                return new DefaultOAuth2RefreshToken(refreshToken.getJti());
            } else {
                return new DefaultOAuth2RefreshToken(refreshToken.getValue());
            }
        }
    }

    boolean isOpaqueTokenRequired(OAuth2Authentication authentication) {
        Map<String, String> parameters = authentication.getOAuth2Request().getRequestParameters();
        return OPAQUE.getStringValue().equals(parameters.get(REQUEST_TOKEN_FORMAT)) ||
                GRANT_TYPE_USER_TOKEN.equals(parameters.get(GRANT_TYPE));
    }

    private static String getUserId(OAuth2Authentication authentication) {
        return Origin.getUserId(authentication.getUserAuthentication());
    }

    private static String generateUniqueTokenId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException {
        if (UaaStringUtils.isEmpty(accessToken)) {
            throw new InvalidTokenException("Invalid access token value, must be at least 30 characters");
        }

        JwtTokenSignedByThisUAA jwtToken =
                tokenValidationService.validateToken(accessToken, true)
                        .checkJti();

        Map<String, Object> claims = jwtToken.getClaims();

        accessToken = jwtToken.getJwt().getEncoded();

        // Check token expiry
        Long expiration = Long.valueOf(claims.get(EXPIRY_IN_SECONDS).toString());
        if (new Date(expiration * MILLIS_PER_SECOND).before(timeService.getCurrentDate())) {
            throw new InvalidTokenException("Invalid access token: expired at " + new Date(expiration * MILLIS_PER_SECOND));
        }

        ArrayList<String> scopes = (ArrayList<String>) claims.get(SCOPE);

        AuthorizationRequest authorizationRequest = new AuthorizationRequest((String) claims.get(CLIENT_ID),
                scopes);

        ArrayList<String> rids = (ArrayList<String>) claims.get(AUD);
        Set<String> resourceIds = Collections.unmodifiableSet(rids == null ? new HashSet<>() : new HashSet<>(rids));
        authorizationRequest.setResourceIds(resourceIds);

        authorizationRequest.setApproved(true);

        Collection<String> defaultUserAuthorities = IdentityZoneHolder.get().getConfig().getUserConfig().getDefaultGroups();
        Collection<? extends GrantedAuthority> authorities =
                AuthorityUtils.commaSeparatedStringToAuthorityList(
                        StringUtils.collectionToCommaDelimitedString(defaultUserAuthorities)
                );
        if (claims.containsKey(AUTHORITIES)) {
            Object authoritiesFromClaims = claims.get(AUTHORITIES);
            if (authoritiesFromClaims instanceof String string) {
                authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(string);
            }
            if (authoritiesFromClaims instanceof Collection<?> collection) {
                authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils
                        .collectionToCommaDelimitedString(collection));
            }
        }

        Authentication userAuthentication = null;
        // Is this a user token - minimum info is user_id
        if (claims.containsKey(USER_ID)) {
            UaaUserPrototype user = userDatabase.retrieveUserPrototypeById((String) claims.get(USER_ID));
            UaaPrincipal principal = new UaaPrincipal(user);
            userAuthentication = new UaaAuthentication(principal, UaaAuthority.USER_AUTHORITIES, null);
        } else {
            authorizationRequest.setAuthorities(authorities);
        }

        OAuth2Authentication authentication = new UaaOauth2Authentication(accessToken,
                IdentityZoneHolder.get().getId(),
                authorizationRequest.createOAuth2Request(),
                userAuthentication);
        authentication.setAuthenticated(true);
        return authentication;
    }

    private static ArrayList<String> getScopesFromRefreshToken(Map<String, Object> claims) {
        if (claims.containsKey(GRANTED_SCOPES)) {
            return (ArrayList<String>) claims.get(GRANTED_SCOPES);
        }
        return (ArrayList<String>) claims.get(SCOPE);
    }

    /**
     * This method is implemented to support older API calls that assume the
     * presence of a token store
     */
    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        JwtTokenSignedByThisUAA jwtToken =
                tokenValidationService.validateToken(accessToken, true).checkJti();

        Map<String, Object> claims = jwtToken.getClaims();
        accessToken = jwtToken.getJwt().getEncoded();

        // Expiry is verified by check_token
        CompositeToken token = new CompositeToken(accessToken);
        token.setTokenType(OAuth2AccessToken.BEARER_TYPE);
        token.setExpiration(new Date(Long.valueOf(claims.get(EXPIRY_IN_SECONDS).toString()) * MILLIS_PER_SECOND));

        ArrayList<String> scopes = (ArrayList<String>) claims.get(SCOPE);
        if (!ObjectUtils.isEmpty(scopes)) {
            token.setScope(new HashSet<>(scopes));
        }
        String clientId = (String) claims.get(CID);
        String userId = (String) claims.get(USER_ID);
        UaaClientDetails client = (UaaClientDetails) clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        // Only check user access tokens
        if (null != userId) {
            ArrayList<String> tokenScopes = (ArrayList<String>) claims.get(SCOPE);
            approvalService.ensureRequiredApprovals(userId, tokenScopes, (String) claims.get(GRANT_TYPE), client);
        }

        return token;
    }

    /**
     * This method is implemented only to support older API calls that assume
     * the presence of a token store
     */
    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        return null;
    }

    protected void setClientDetailsService(MultitenantClientServices clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    private void publish(TokenIssuedEvent event) {
        if (applicationEventPublisher != null) {
            applicationEventPublisher.publishEvent(event);
        }
    }

    public TokenPolicy getTokenPolicy() {
        return tokenPolicy;
    }

    protected void setTokenEndpointBuilder(TokenEndpointBuilder tokenEndpointBuilder) {
        this.tokenEndpointBuilder = tokenEndpointBuilder;
    }

    public void setTimeService(TimeService timeService) {
        this.timeService = timeService;
    }
}
