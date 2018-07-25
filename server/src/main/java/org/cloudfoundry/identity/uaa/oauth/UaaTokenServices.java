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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenCreationException;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.openid.UserAuthenticationData;
import org.cloudfoundry.identity.uaa.oauth.refresh.CompositeExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenRequestData;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthUserAuthority;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TokenValidation;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
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
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ADDITIONAL_AZ_ATTR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUD;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUTHORITIES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUTH_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AZP;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXP;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANTED_SCOPES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.IAT;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.NONCE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ORIGIN;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.REVOCABLE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.REVOCATION_SIGNATURE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SCOPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ZONE_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenFormat.JWT;
import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenFormat.OPAQUE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.util.TokenValidation.buildAccessTokenValidator;
import static org.cloudfoundry.identity.uaa.util.TokenValidation.buildRefreshTokenValidator;
import static org.springframework.util.StringUtils.hasText;


/**
 * This class provides token services for the UAA. It handles the production and
 * consumption of UAA tokens.
 *
 */
public class UaaTokenServices implements AuthorizationServerTokenServices, ResourceServerTokenServices,
                InitializingBean, ApplicationEventPublisherAware {

    private final Log logger = LogFactory.getLog(getClass());

    private UaaUserDatabase userDatabase = null;

    private ClientServicesExtension clientDetailsService = null;

    private ApprovalStore approvalStore = null;

    private ApplicationEventPublisher applicationEventPublisher;

    private TokenPolicy tokenPolicy;

    private RevocableTokenProvisioning tokenProvisioning;

    private Set<String> excludedClaims = Collections.EMPTY_SET;

    private UaaTokenEnhancer uaaTokenEnhancer = null;
    private IdTokenCreator idTokenCreator;
    private RefreshTokenCreator refreshTokenCreator;
    private TokenEndpointBuilder tokenEndpointBuilder;

    private TokenValidityResolver accessTokenValidityResolver;

    public Set<String> getExcludedClaims() {
        return excludedClaims;
    }

    public void setExcludedClaims(Set<String> excludedClaims) {
        this.excludedClaims = excludedClaims;
    }

    public RevocableTokenProvisioning getTokenProvisioning() {
        return tokenProvisioning;
    }

    public void setTokenProvisioning(RevocableTokenProvisioning tokenProvisioning) {
        this.tokenProvisioning = tokenProvisioning;
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

        if (!"refresh_token".equals(request.getRequestParameters().get("grant_type"))) {
            throw new InvalidGrantException("Invalid grant type: "
                            + request.getRequestParameters().get("grant_type"));
        }

        TokenValidation tokenValidation = validateToken(refreshTokenValue, false);
        Map<String, Object> claims = new HashMap<String,Object>(tokenValidation.getClaims()) {
            @Override
            public Object get(Object key) {
                return super.remove(key);
            }
        };
        refreshTokenValue = tokenValidation.getJwt().getEncoded();

        @SuppressWarnings("unchecked")
        ArrayList<String> tokenScopes = getScopesFromRefreshToken(claims);

        refreshTokenCreator.ensureRefreshTokenCreationNotRestricted(tokenScopes);

        String clientId = (String) claims.get(CID);
        if (clientId == null || !clientId.equals(request.getClientId())) {
            throw new InvalidGrantException("Wrong client for this refresh token: " + clientId);
        }
        //remove known claims
        claims.remove(CLIENT_ID);
        claims.remove(ORIGIN);
        claims.remove(SUB);
        claims.remove(ISS);
        claims.remove(USER_NAME);
        claims.remove(ZONE_ID);
        claims.remove(IAT);

        String userid = (String) claims.get(USER_ID);

        String refreshTokenId = (String) claims.get(JTI);
        String accessTokenId = generateUniqueTokenId();

        boolean opaque = TokenConstants.OPAQUE.equals(request.getRequestParameters().get(TokenConstants.REQUEST_TOKEN_FORMAT));
        Boolean revocableClaim = (Boolean)claims.get(REVOCABLE);
        boolean revocable = opaque || (revocableClaim == null ? false : revocableClaim);

        UaaUser user = userDatabase.retrieveUserById(userid);
        ClientDetails client = clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());

        Integer refreshTokenExpiry = (Integer) claims.get(EXP);
        long refreshTokenExpireDate = refreshTokenExpiry.longValue() * 1000l;

        if (new Date(refreshTokenExpireDate).before(new Date())) {
            throw new InvalidTokenException("Invalid refresh token expired at " + new Date(refreshTokenExpireDate));
        }

        // default request scopes to what is in the refresh token
        Set<String> requestedScopes = request.getScope();
        if (requestedScopes.isEmpty()) {
            requestedScopes = new HashSet<>(tokenScopes);
        }

        // The user may not request scopes that were not part of the refresh
        // token
        if (tokenScopes.isEmpty() || !tokenScopes.containsAll(requestedScopes)) {
            throw new InvalidScopeException("Unable to narrow the scope of the client authentication to "
                            + requestedScopes + ".", new HashSet<>(tokenScopes));
        }

        // from this point on, we only care about the scopes requested, not what
        // is in the refresh token
        // ensure all requested scopes are approved: either automatically or
        // explicitly by the user
        String grantType = claims.get(GRANT_TYPE).toString();
        checkForApproval(userid, clientId, requestedScopes,
                        getAutoApprovedScopes(grantType, tokenScopes, client)
        );

        String nonce = (String) claims.get(NONCE);

        @SuppressWarnings("unchecked")
        Map<String, String> additionalAuthorizationInfo = (Map<String, String>) claims.get(ADDITIONAL_AZ_ATTR);

        String revocableHashSignature = (String)claims.get(REVOCATION_SIGNATURE);
        if (hasText(revocableHashSignature)) {
            String clientSecretForHash = client.getClientSecret();
            if(clientSecretForHash != null && clientSecretForHash.split(" ").length > 1){
                clientSecretForHash = clientSecretForHash.split(" ")[1];
            }
            String newRevocableHashSignature = UaaTokenUtils.getRevocableTokenSignature(client, clientSecretForHash, user);
            if (!revocableHashSignature.equals(newRevocableHashSignature)) {
                throw new TokenRevokedException("Invalid refresh token: revocable signature mismatch");
            }
        }

        Set<String> audience = new HashSet<>((ArrayList<String>)claims.get(AUD));

        Map<String, Object> additionalRootClaims = new HashMap<>();
        claims.entrySet()
            .stream()
            .forEach(
                entry -> additionalRootClaims.put(entry.getKey(), entry.getValue())
            );

        CompositeAccessToken accessToken =
            createAccessToken(
                accessTokenId,
                user.getId(),
                user,
                (claims.get(AUTH_TIME) != null) ? new Date(((Long) claims.get(AUTH_TIME)) * 1000l) : null,
                null,
                requestedScopes,
                clientId,
                audience /*request.createOAuth2Request(client).getResourceIds()*/,
                grantType,
                refreshTokenValue,
                nonce,
                additionalAuthorizationInfo,
                additionalRootClaims,
                new HashSet<>(),
                revocableHashSignature,
                false,
                null,  //TODO populate response types
                null,
                revocable,
                null,
                null);

        CompositeExpiringOAuth2RefreshToken expiringRefreshToken = new CompositeExpiringOAuth2RefreshToken(refreshTokenValue, new Date(refreshTokenExpireDate), refreshTokenId);
        return persistRevocableToken(accessTokenId, accessToken, expiringRefreshToken, clientId, user.getId(), opaque, revocable);

    }

    private void checkForApproval(String userid,
                                  String clientId,
                                  Collection<String> requestedScopes,
                                  Collection<String> autoApprovedScopes) {
        if(autoApprovedScopes.containsAll(requestedScopes)) { return; }
        Set<String> approvedScopes = new HashSet<>(autoApprovedScopes);

        // Search through the users approvals for scopes that are requested, not
        // auto approved, not expired,
        // not DENIED and not approved more recently than when this access token
        // was issued.
        List<Approval> approvals = approvalStore.getApprovals(userid, clientId, IdentityZoneHolder.get().getId());
        for (Approval approval : approvals) {
            if (requestedScopes.contains(approval.getScope()) && approval.getStatus() == ApprovalStatus.APPROVED) {
                if (!approval.isCurrentlyActive()) {
                    logger.debug("Approval " + approval + " has expired. Need to re-approve.");
                    throw new InvalidTokenException("Invalid token (approvals expired)");
                }
                approvedScopes.add(approval.getScope());
            }
        }

        // Only issue the token if all the requested scopes have unexpired
        // approvals made before the refresh token was
        // issued OR if those scopes are auto approved
        if (!approvedScopes.containsAll(requestedScopes)) {
            logger.debug("All requested scopes " + requestedScopes + " were not approved " + approvedScopes);
            Set<String> unapprovedScopes = new HashSet<String>(requestedScopes);
            unapprovedScopes.removeAll(approvedScopes);
            throw new InvalidTokenException("Invalid token (some requested scopes are not approved): "
                            + unapprovedScopes);
        }
    }


    private CompositeAccessToken createAccessToken(String tokenId,
                                                   String userId,
                                                   UaaUser user,
                                                   Date userAuthenticationTime,
                                                   Collection<GrantedAuthority> clientScopes,
                                                   Set<String> requestedScopes,
                                                   String clientId,
                                                   Set<String> resourceIds,
                                                   String grantType,
                                                   String refreshToken,
                                                   String nonce,
                                                   Map<String, String> additionalAuthorizationAttributes,
                                                   Map<String, Object> additionalRootClaims,
                                                   Set<String> responseTypes,
                                                   String revocableHashSignature,
                                                   boolean forceIdTokenCreation,
                                                   Set<String> externalGroupsForIdToken,
                                                   Map<String, List<String>> userAttributesForIdToken,
                                                   boolean revocable,
                                                   Set<String> authenticationMethods,
                                                   Set<String> authNContextClassRef) throws AuthenticationException {
        CompositeAccessToken accessToken = new CompositeAccessToken(tokenId);
        accessToken.setExpiration(accessTokenValidityResolver.resolve(clientId));
        accessToken.setRefreshToken(refreshToken == null ? null : new DefaultOAuth2RefreshToken(refreshToken));

        if (null == requestedScopes || requestedScopes.size() == 0) {
            logger.debug("No scopes were granted");
            throw new InvalidTokenException("No scopes were granted");
        }

        accessToken.setScope(requestedScopes);

        ConcurrentMap<String, Object> info = new ConcurrentHashMap<>();
        info.put(JTI, accessToken.getValue());
        if (null != additionalAuthorizationAttributes) {
            info.put(ADDITIONAL_AZ_ATTR, additionalAuthorizationAttributes);
        }

        if (nonce != null) {
            info.put(NONCE, nonce);
        }

        accessToken.setAdditionalInformation(info);

        String content;
        Map<String, ?> jwtAccessToken = createJWTAccessToken(
            accessToken,
            userId,
            user,
            userAuthenticationTime,
            clientScopes,
            requestedScopes,
            clientId,
            resourceIds,
            grantType,
            revocableHashSignature,
            revocable,
            additionalRootClaims
        );
        try {
            content = JsonUtils.writeValueAsString(jwtAccessToken);
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        String token = JwtHelper.encode(content, getActiveKeyInfo().getSigner()).getEncoded();
        // This setter copies the value and returns. Don't change.
        accessToken.setValue(token);
        if (shouldSendIdToken(clientScopes, requestedScopes, grantType, responseTypes, forceIdTokenCreation)) {
            UserAuthenticationData authenticationData = new UserAuthenticationData(userAuthenticationTime,
                authenticationMethods,
                authNContextClassRef,
                requestedScopes,
                externalGroupsForIdToken,
                userAttributesForIdToken,
                nonce,
                grantType,
                tokenId);

            String idTokenContent = null;
            try {
                idTokenContent = JsonUtils.writeValueAsString(idTokenCreator.create(clientId, userId, authenticationData));
            } catch (RuntimeException | IdTokenCreationException e) {
                throw new IllegalStateException("Cannot convert id token to JSON");
            }
            String encodedIdTokenContent = JwtHelper.encode(idTokenContent, KeyInfo.getActiveKey().getSigner()).getEncoded();
            accessToken.setIdTokenValue(encodedIdTokenContent);
        }

        publish(new TokenIssuedEvent(accessToken, SecurityContextHolder.getContext().getAuthentication()));

        return accessToken;
    }

    private boolean shouldSendIdToken(Collection<GrantedAuthority> clientScopes, Set<String> requestedScopes, String grantType, Set<String> responseTypes, boolean forceIdTokenCreation) {
        boolean clientHasOpenIdScope = false;
        if(null != clientScopes && !"client_credentials".equals(grantType)) {
            for (GrantedAuthority scope : clientScopes) {
                if (scope.getAuthority().equals("openid")) {
                    clientHasOpenIdScope = true;
                    break;
                }
            }
        }

        boolean idTokenExplicitlyRequested = requestedScopes.contains("openid") && responseTypes.contains(CompositeAccessToken.ID_TOKEN);
        return forceIdTokenCreation || idTokenExplicitlyRequested || clientHasOpenIdScope;
    }

    private KeyInfo getActiveKeyInfo() {
        return ofNullable(KeyInfo.getActiveKey())
            .orElseThrow(() -> new InternalAuthenticationServiceException("Unable to sign token, misconfigured JWT signing keys"));
    }

    private Map<String, ?> createJWTAccessToken(OAuth2AccessToken token,
                                                String userId,
                                                UaaUser user,
                                                Date userAuthenticationTime,
                                                Collection<GrantedAuthority> clientScopes,
                                                Set<String> requestedScopes,
                                                String clientId,
                                                Set<String> resourceIds,
                                                String grantType,
                                                String revocableHashSignature,
                                                boolean revocable,
                                                Map<String, Object> additionalRootClaims) {

        Map<String, Object> claims = new LinkedHashMap<>();

        claims.put(JTI, token.getAdditionalInformation().get(JTI));
        claims.putAll(token.getAdditionalInformation());

        if(additionalRootClaims != null) {
            claims.putAll(additionalRootClaims);
        }

        claims.put(SUB, clientId);
        if ("client_credentials".equals(grantType)) {
            claims.put(AUTHORITIES, AuthorityUtils.authorityListToSet(clientScopes));
        }

        claims.put(OAuth2AccessToken.SCOPE, requestedScopes);
        claims.put(CLIENT_ID, clientId);
        claims.put(CID, clientId);
        claims.put(AZP, clientId); //openId Connect
        if (revocable) {
            claims.put(REVOCABLE, true);
        }

        if (null != grantType) {
            claims.put(GRANT_TYPE, grantType);
        }
        if (user!=null && userId!=null) {
            claims.put(USER_ID, userId);
            String origin = user.getOrigin();
            if (StringUtils.hasLength(origin)) {
                claims.put(ORIGIN, origin);
            }
            String username = user.getUsername();
            claims.put(USER_NAME, username == null ? userId : username);
            String userEmail = user.getEmail();
            if (userEmail != null) {
                claims.put(EMAIL, userEmail);
            }
            if (userAuthenticationTime!=null) {
                claims.put(AUTH_TIME, userAuthenticationTime.getTime() / 1000);
            }
            claims.put(SUB, userId);
        }

        if (StringUtils.hasText(revocableHashSignature)) {
            claims.put(REVOCATION_SIGNATURE, revocableHashSignature);
        }

        claims.put(IAT, System.currentTimeMillis() / 1000);
        claims.put(EXP, token.getExpiration().getTime() / 1000);

        if (tokenEndpointBuilder.getTokenEndpoint() != null) {
            claims.put(ISS, tokenEndpointBuilder.getTokenEndpoint());
            claims.put(ZONE_ID,IdentityZoneHolder.get().getId());
        }

        // TODO: different values for audience in the AT and RT. Need to sync
        // them up
        claims.put(AUD, resourceIds);

        for (String excludedClaim : getExcludedClaims()) {
            claims.remove(excludedClaim);
        }

        return claims;
    }

    @Override
    public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {

        String userId = null;
        Date userAuthenticationTime = null;
        UaaUser user = null;
        boolean wasIdTokenRequestedThroughAuthCodeScopeParameter = false;

        Set<String> authenticationMethods = null;
        Set<String> authNContextClassRef = null;

        OAuth2Request oAuth2Request = authentication.getOAuth2Request();
        ClientDetails client = clientDetailsService.loadClientByClientId(oAuth2Request.getClientId(), IdentityZoneHolder.get().getId());
        Collection<GrantedAuthority> clientScopes = null;

        // Clients should really by different kinds of users
        if (authentication.isClientOnly()) {
            clientScopes = client.getAuthorities();
        } else {
            clientScopes = new ArrayList<GrantedAuthority>();
            for(String scope : client.getScope()) {
                clientScopes.add(new XOAuthUserAuthority(scope));
            }
            userId = getUserId(authentication);
            user = userDatabase.retrieveUserById(userId);
            if (authentication.getUserAuthentication() instanceof UaaAuthentication) {
                userAuthenticationTime = new Date(((UaaAuthentication)authentication.getUserAuthentication()).getAuthenticatedTime());
                authenticationMethods = ((UaaAuthentication) authentication.getUserAuthentication()).getAuthenticationMethods();
                authNContextClassRef = ((UaaAuthentication) authentication.getUserAuthentication()).getAuthContextClassRef();
            }
            validateRequiredUserGroups(user, client);
        }


        String clientSecretForHash = client.getClientSecret();
        if(clientSecretForHash != null && clientSecretForHash.split(" ").length > 1){
            clientSecretForHash = clientSecretForHash.split(" ")[1];
        }
        String revocableHashSignature = UaaTokenUtils.getRevocableTokenSignature(client, clientSecretForHash, user);

        String tokenId = generateUniqueTokenId();

        boolean opaque = opaqueTokenRequired(authentication);
        boolean accessTokenRevocable = opaque || IdentityZoneHolder.get().getConfig().getTokenPolicy().isJwtRevocable();
        boolean refreshTokenRevocable = accessTokenRevocable || TokenConstants.TokenFormat.OPAQUE.getStringValue().equals(IdentityZoneHolder.get().getConfig().getTokenPolicy().getRefreshTokenFormat());

        CompositeExpiringOAuth2RefreshToken refreshToken = null;
        Map<String,Object> additionalRootClaims = null;

        if (uaaTokenEnhancer != null) {
            additionalRootClaims = new HashMap<>();
            additionalRootClaims.putAll(uaaTokenEnhancer.enhance(emptyMap(), authentication));
        }

        if(client.getAuthorizedGrantTypes().contains(GRANT_TYPE_REFRESH_TOKEN)){
            RefreshTokenRequestData refreshTokenRequestData = new RefreshTokenRequestData(
                oAuth2Request.getGrantType(),
                oAuth2Request.getScope(),
                oAuth2Request.getRequestParameters().get("authorities"),
                oAuth2Request.getResourceIds(),
                oAuth2Request.getClientId(),
                refreshTokenRevocable,
                additionalRootClaims
            );
            refreshToken = refreshTokenCreator.createRefreshToken(user, refreshTokenRequestData, revocableHashSignature);
        }

        String clientId = oAuth2Request.getClientId();
        Set<String> userScopes = oAuth2Request.getScope();
        Map<String, String> requestParameters = oAuth2Request.getRequestParameters();
        String grantType = requestParameters.get("grant_type");

        Set<String> modifiableUserScopes = new LinkedHashSet<>(userScopes);

        Set<String> externalGroupsForIdToken = Collections.EMPTY_SET;
        Map<String,List<String>> userAttributesForIdToken = Collections.EMPTY_MAP;
        if (authentication.getUserAuthentication() instanceof UaaAuthentication) {
            externalGroupsForIdToken = ((UaaAuthentication)authentication.getUserAuthentication()).getExternalGroups();
            userAttributesForIdToken = ((UaaAuthentication)authentication.getUserAuthentication()).getUserAttributes();
        }

        String nonce = requestParameters.get(NONCE);

        Map<String, String> additionalAuthorizationAttributes =
            new AuthorizationAttributesParser().getAdditionalAuthorizationAttributes(
                requestParameters.get("authorities")
            );

        if ("authorization_code".equals(requestParameters.get(OAuth2Utils.GRANT_TYPE)) &&
            "code".equals(requestParameters.get(OAuth2Utils.RESPONSE_TYPE)) &&
            requestParameters.get(OAuth2Utils.SCOPE)!=null &&
            Arrays.asList(requestParameters.get(OAuth2Utils.SCOPE).split(" ")).contains("openid")) {
            wasIdTokenRequestedThroughAuthCodeScopeParameter = true;
        }

        Set<String> responseTypes = extractResponseTypes(authentication);

        CompositeAccessToken accessToken =
            createAccessToken(
                tokenId,
                userId,
                user,
                userAuthenticationTime,
                clientScopes,
                modifiableUserScopes,
                clientId,
                oAuth2Request.getResourceIds(),
                grantType,
                refreshToken != null ? refreshToken.getValue() : null,
                nonce,
                additionalAuthorizationAttributes,
                additionalRootClaims,
                responseTypes,
                revocableHashSignature,
                wasIdTokenRequestedThroughAuthCodeScopeParameter,
                externalGroupsForIdToken,
                userAttributesForIdToken,
                accessTokenRevocable,
                authenticationMethods,
                authNContextClassRef);

        return persistRevocableToken(tokenId, accessToken, refreshToken, clientId, userId, opaque, accessTokenRevocable);
    }

    public static void validateRequiredUserGroups(UaaUser user, ClientDetails client) {
        Collection<String> requiredUserGroups = ofNullable((Collection<String>) client.getAdditionalInformation().get(REQUIRED_USER_GROUPS)).orElse(emptySet());
        if (!UaaTokenUtils.hasRequiredUserAuthorities(requiredUserGroups, user.getAuthorities())) {
            throw new InvalidTokenException("User does not meet the client's required group criteria.");
        }
    }

    public CompositeAccessToken persistRevocableToken(String tokenId,
                                                      CompositeAccessToken token,
                                                      CompositeExpiringOAuth2RefreshToken refreshToken,
                                                      String clientId,
                                                      String userId,
                                                      boolean opaque,
                                                      boolean revocable) {

        String scope = token.getScope().toString();
        long now = System.currentTimeMillis();
        if (revocable) {
            RevocableToken revocableAccessToken = new RevocableToken()
                .setTokenId(tokenId)
                .setClientId(clientId)
                .setExpiresAt(token.getExpiration().getTime())
                .setIssuedAt(now)
                .setFormat(opaque ? OPAQUE.name() : JWT.name())
                .setResponseType(RevocableToken.TokenType.ACCESS_TOKEN)
                .setZoneId(IdentityZoneHolder.get().getId())
                .setUserId(userId)
                .setScope(scope)
                .setValue(token.getValue());
            try {
                tokenProvisioning.create(revocableAccessToken, IdentityZoneHolder.get().getId());
            } catch (DuplicateKeyException updateInstead) {
                //TODO this is an uninteded side effect of reusing access token IDs
                tokenProvisioning.update(tokenId, revocableAccessToken, IdentityZoneHolder.get().getId());
            }
        }

        boolean refreshTokenOpaque = opaque || TokenConstants.TokenFormat.OPAQUE.getStringValue().equals(IdentityZoneHolder.get().getConfig().getTokenPolicy().getRefreshTokenFormat());
        boolean refreshTokenRevocable = refreshTokenOpaque || IdentityZoneHolder.get().getConfig().getTokenPolicy().isJwtRevocable();
        boolean refreshTokenUnique = IdentityZoneHolder.get().getConfig().getTokenPolicy().isRefreshTokenUnique();
        if (refreshToken != null && refreshTokenRevocable) {
            RevocableToken revocableRefreshToken = new RevocableToken()
                .setTokenId(refreshToken.getJti())
                .setClientId(clientId)
                .setExpiresAt(refreshToken.getExpiration().getTime())
                .setIssuedAt(now)
                .setFormat(refreshTokenOpaque ? OPAQUE.name() : JWT.name())
                .setResponseType(RevocableToken.TokenType.REFRESH_TOKEN)
                .setZoneId(IdentityZoneHolder.get().getId())
                .setUserId(userId)
                .setScope(scope)
                .setValue(refreshToken.getValue());
            try {
                if(refreshTokenUnique) {
                    tokenProvisioning.deleteRefreshTokensForClientAndUserId(clientId, userId, IdentityZoneHolder.get().getId());
                }
                tokenProvisioning.create(revocableRefreshToken, IdentityZoneHolder.get().getId());
            } catch (DuplicateKeyException ignore) {
                //no need to store refresh tokens again
            }
        }

        CompositeAccessToken result = new CompositeAccessToken(opaque ? tokenId : token.getValue());
        result.setIdTokenValue(token.getIdTokenValue());
        result.setExpiration(token.getExpiration());
        result.setAdditionalInformation(token.getAdditionalInformation());
        result.setScope(token.getScope());
        result.setTokenType(token.getTokenType());
        result.setRefreshToken(refreshToken==null ? null : new DefaultOAuth2RefreshToken(refreshTokenOpaque ? refreshToken == null ? null : refreshToken.getJti() : refreshToken.getValue()));
        return result;
    }

    protected boolean opaqueTokenRequired(OAuth2Authentication authentication) {
        Map<String, String> parameters = authentication.getOAuth2Request().getRequestParameters();
        return TokenConstants.OPAQUE.equals(parameters.get(REQUEST_TOKEN_FORMAT)) ||
            GRANT_TYPE_USER_TOKEN.equals(parameters.get(GRANT_TYPE));
    }

    /**
     * If an only if the stored request has response_type=code AND
     * the request parameters override it using another response_type parameter
     * this method will return the requested response_type rather than the stored
     * @param authentication
     * @return
     */
    protected Set<String> extractResponseTypes(OAuth2Authentication authentication) {
        Set<String> responseTypes = authentication.getOAuth2Request().getResponseTypes();
        if (responseTypes!=null && responseTypes.size()==1) {
            String storedResponseType = responseTypes.iterator().next();
            String requesedResponseType = authentication.getOAuth2Request().getRequestParameters().get(OAuth2Utils.RESPONSE_TYPE);
            if ("code".equals(storedResponseType) &&
                requesedResponseType!=null) {
                responseTypes = OAuth2Utils.parseParameterList(requesedResponseType);
            }
        }
        return responseTypes;
    }

    protected String getUserId(OAuth2Authentication authentication) {
        return Origin.getUserId(authentication.getUserAuthentication());
    }

    protected String generateUniqueTokenId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    @Override
    public void afterPropertiesSet() throws URISyntaxException {
        Assert.notNull(clientDetailsService, "clientDetailsService must be set");
        Assert.notNull(approvalStore, "approvalStore must be set");
    }

    public void setUserDatabase(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException {
        if (StringUtils.isEmpty(accessToken)) {
            throw new InvalidTokenException("Invalid access token value, must be at least 30 characters");
        }

        TokenValidation tokenValidation =
          validateToken(accessToken, true)
          .checkAccessToken();

        Map<String, Object> claims = tokenValidation.getClaims();

        accessToken = tokenValidation.getJwt().getEncoded();

        // Check token expiry
        Long expiration = Long.valueOf(claims.get(EXP).toString());
        if (expiration != null && new Date(expiration * 1000L).before(new Date())) {
            throw new InvalidTokenException("Invalid access token: expired at " + new Date(expiration * 1000L));
        }

        @SuppressWarnings("unchecked")
        ArrayList<String> scopes = (ArrayList<String>) claims.get(SCOPE);

        AuthorizationRequest authorizationRequest = new AuthorizationRequest((String) claims.get(CLIENT_ID),
                        scopes);

        ArrayList<String> rids = (ArrayList<String>) claims.get(AUD);
        //TODO - Fix null resource IDs for a client_credentials request to /oauth/token
        Set<String> resourceIds = Collections.unmodifiableSet(rids==null?new HashSet<>():new HashSet<>(rids));
        authorizationRequest.setResourceIds(resourceIds);

        authorizationRequest.setApproved(true);

        Collection<String> defaultUserAuthorities = IdentityZoneHolder.get().getConfig().getUserConfig().getDefaultGroups();
        Collection<? extends GrantedAuthority> authorities =
            AuthorityUtils.commaSeparatedStringToAuthorityList(
                StringUtils.collectionToCommaDelimitedString(defaultUserAuthorities)
            );
        if (claims.containsKey("authorities")) {
            Object authoritiesFromClaims = claims.get("authorities");
            if (authoritiesFromClaims instanceof String) {
                authorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) authoritiesFromClaims);
            }
            if (authoritiesFromClaims instanceof Collection) {
                authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils
                                .collectionToCommaDelimitedString((Collection<?>) authoritiesFromClaims));
            }
        }

        Authentication userAuthentication = null;
        // Is this a user token - minimum info is user_id
        if (claims.containsKey(USER_ID)) {
            UaaUser user = userDatabase.retrieveUserById((String)claims.get(USER_ID));
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

    private ArrayList<String> getScopesFromRefreshToken(Map<String, Object> claims) {
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
        TokenValidation tokenValidation =
          validateToken(accessToken, true)
            .checkAccessToken();

        Map<String, Object> claims = tokenValidation.getClaims();
        accessToken = tokenValidation.getJwt().getEncoded();

        // Expiry is verified by check_token
        CompositeAccessToken token = new CompositeAccessToken(accessToken);
        token.setTokenType(OAuth2AccessToken.BEARER_TYPE);
        Long exp = Long.valueOf(claims.get(EXP).toString());
        if (null != exp) {
            token.setExpiration(new Date(exp.longValue() * 1000l));
        }

        @SuppressWarnings("unchecked")
        ArrayList<String> scopes = (ArrayList<String>) claims.get(SCOPE);
        if (null != scopes && scopes.size() > 0) {
            token.setScope(new HashSet<>(scopes));
        }
        String clientId = (String) claims.get(CID);
        ClientDetails client = clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        String userId = (String)claims.get(USER_ID);
        // Only check user access tokens
        if (null != userId) {
            @SuppressWarnings("unchecked")
            ArrayList<String> tokenScopes = (ArrayList<String>) claims.get(SCOPE);
            Set<String> autoApprovedScopes = getAutoApprovedScopes(claims.get(GRANT_TYPE), tokenScopes, client);
            checkForApproval(userId, clientId, tokenScopes, autoApprovedScopes);
        }

        return token;
    }

    private Set<String> getAutoApprovedScopes(Object grantType, Collection<String> tokenScopes, ClientDetails client) {
        // ALL requested scopes are considered auto-approved for password grant
        if (grantType != null && "password".equals(grantType.toString())) {
            return new HashSet<>(tokenScopes);
        }
        BaseClientDetails clientDetails = (BaseClientDetails) client;

        return UaaTokenUtils.retainAutoApprovedScopes(tokenScopes, clientDetails.getAutoApproveScopes());
    }

    protected TokenValidation validateToken(String token, boolean isAccessToken) {
        if (!UaaTokenUtils.isJwtToken(token)) {
            RevocableToken revocableToken;
            try {
                revocableToken = tokenProvisioning.retrieve(token, IdentityZoneHolder.get().getId());
            } catch(EmptyResultDataAccessException ex) {
                throw new TokenRevokedException("The token expired, was revoked, or the token ID is incorrect.");
            }
            token = revocableToken.getValue();
        }

        TokenValidation tokenValidation = isAccessToken ?
            buildAccessTokenValidator(token) : buildRefreshTokenValidator(token);
        tokenValidation
            .checkRevocableTokenStore(tokenProvisioning)
            .checkIssuer(tokenEndpointBuilder.getTokenEndpoint());

        ClientDetails client = tokenValidation.getClientDetails(clientDetailsService);
        UaaUser user = tokenValidation.getUserDetails(userDatabase);
        tokenValidation
            .checkClientAndUser(client, user);

        List<String> clientSecrets = new ArrayList<>();
        List<String> revocationSignatureList = new ArrayList<>();
        if (client.getClientSecret() != null) {
            clientSecrets.addAll(Arrays.asList(client.getClientSecret().split(" ")));
        } else {
            revocationSignatureList.add(UaaTokenUtils.getRevocableTokenSignature(client, null, user));
        }

        for (String clientSecret : clientSecrets) {
            revocationSignatureList.add(UaaTokenUtils.getRevocableTokenSignature(client, clientSecret, user));
        }

        tokenValidation = tokenValidation.checkRevocationSignature(revocationSignatureList);

        return tokenValidation;
    }

    /**
     * This method is implemented only to support older API calls that assume
     * the presence of a token store
     */
    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        return null;
    }

    public void setClientDetailsService(ClientServicesExtension clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setApprovalStore(ApprovalStore approvalStore) {
        this.approvalStore = approvalStore;
    }

    private void publish(TokenIssuedEvent event) {
        if (applicationEventPublisher != null) {
            applicationEventPublisher.publishEvent(event);
        }
    }

    public void setTokenPolicy(TokenPolicy tokenPolicy) {
        this.tokenPolicy = tokenPolicy;
    }

    public TokenPolicy getTokenPolicy() {
        return tokenPolicy;
    }

    public void setIdTokenCreator(IdTokenCreator idTokenCreator) {
        this.idTokenCreator = idTokenCreator;
    }

    public void setAccessTokenValidityResolver(TokenValidityResolver accessTokenValidityResolver) {
        this.accessTokenValidityResolver = accessTokenValidityResolver;
    }

    public void setRefreshTokenCreator(RefreshTokenCreator refreshTokenCreator) {
        this.refreshTokenCreator = refreshTokenCreator;
    }

    public void setTokenEndpointBuilder(TokenEndpointBuilder tokenEndpointBuilder) {
        this.tokenEndpointBuilder = tokenEndpointBuilder;
    }
}
