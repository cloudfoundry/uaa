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

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
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
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthUserAuthority;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TokenValidation;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.util.Collections.emptyMap;
import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.*;
import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenFormat.JWT;
import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenFormat.OPAQUE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.*;
import static org.springframework.util.StringUtils.hasText;


/**
 * This class provides token services for the UAA. It handles the production and
 * consumption of UAA tokens.
 *
 */
public class UaaTokenServices implements AuthorizationServerTokenServices, ResourceServerTokenServices, ApplicationEventPublisherAware {

    private final Log logger = LogFactory.getLog(getClass());

    private UaaUserDatabase userDatabase;

    private ClientServicesExtension clientDetailsService;

    private ApprovalStore approvalStore;

    private ApplicationEventPublisher applicationEventPublisher;

    private TokenPolicy tokenPolicy;

    private RevocableTokenProvisioning tokenProvisioning;

    private Set<String> excludedClaims;

    private UaaTokenEnhancer uaaTokenEnhancer = null;
    private IdTokenCreator idTokenCreator;
    private RefreshTokenCreator refreshTokenCreator;
    private TokenEndpointBuilder tokenEndpointBuilder;
    private TimeService timeService;
    private TokenValidityResolver accessTokenValidityResolver;
    private TokenValidationService tokenValidationService;

    public UaaTokenServices(IdTokenCreator idTokenCreator,
                            TokenEndpointBuilder tokenEndpointBuilder,
                            ClientServicesExtension clientDetailsService,
                            RevocableTokenProvisioning revocableTokenProvisioning,
                            TokenValidationService tokenValidationService,
                            RefreshTokenCreator refreshTokenCreator,
                            TimeService timeService,
                            TokenValidityResolver accessTokenValidityResolver,
                            UaaUserDatabase userDatabase,
                            ApprovalStore approvalStore,
                            Set<String> excludedClaims,
                            TokenPolicy globalTokenPolicy){
        this.idTokenCreator = idTokenCreator;
        this.tokenEndpointBuilder = tokenEndpointBuilder;
        this.clientDetailsService = clientDetailsService;
        this.tokenProvisioning = revocableTokenProvisioning;
        this.tokenValidationService = tokenValidationService;
        this.refreshTokenCreator = refreshTokenCreator;
        this.timeService = timeService;
        this.accessTokenValidityResolver = accessTokenValidityResolver;
        this.userDatabase = userDatabase;
        this.approvalStore = approvalStore;
        this.excludedClaims = excludedClaims;
        this.tokenPolicy = globalTokenPolicy;
    }

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

        TokenValidation tokenValidation = tokenValidationService
                .validateToken(refreshTokenValue, false)
                .checkJti();
        Map<String, Object> refreshTokenClaims = tokenValidation.getClaims();

        @SuppressWarnings("unchecked")
        ArrayList<String> tokenScopes = getScopesFromRefreshToken(refreshTokenClaims);

        refreshTokenCreator.ensureRefreshTokenCreationNotRestricted(tokenScopes);

        String clientId = (String) refreshTokenClaims.get(CID);
        if (clientId == null || !clientId.equals(request.getClientId())) {
            throw new InvalidGrantException("Wrong client for this refresh token: " + clientId);
        }

        String userId = (String) refreshTokenClaims.get(USER_ID);
        String refreshTokenId = (String) refreshTokenClaims.get(JTI);
        String accessTokenId = generateUniqueTokenId();

        boolean opaque = TokenConstants.OPAQUE.equals(request.getRequestParameters().get(TokenConstants.REQUEST_TOKEN_FORMAT));
        Boolean revocableClaim = (Boolean)refreshTokenClaims.get(REVOCABLE);
        boolean revocable = opaque || (revocableClaim == null ? false : revocableClaim);

        UaaUser user = userDatabase.retrieveUserById(userId);
        ClientDetails client = clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());

        Integer refreshTokenExpiry = (Integer) refreshTokenClaims.get(EXP);
        long refreshTokenExpireDate = refreshTokenExpiry.longValue() * 1000L;

        if (new Date(refreshTokenExpireDate).before(new Date(timeService.getCurrentTimeMillis()))) {
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
        String grantType = refreshTokenClaims.get(GRANT_TYPE).toString();
        checkForApproval(userId, clientId, requestedScopes,
                        getAutoApprovedScopes(grantType, tokenScopes, client)
        );

        String nonce = (String) refreshTokenClaims.get(NONCE);

        @SuppressWarnings("unchecked")
        Map<String, String> additionalAuthorizationInfo = (Map<String, String>) refreshTokenClaims.get(ADDITIONAL_AZ_ATTR);

        String revocableHashSignature = (String)refreshTokenClaims.get(REVOCATION_SIGNATURE);
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

        Set<String> audience = new HashSet<>((ArrayList<String>)refreshTokenClaims.get(AUD));

        Map<String, Object> additionalRootClaims = new HashMap<>();
        refreshTokenClaims.entrySet()
            .stream()
            .forEach(
                entry -> additionalRootClaims.put(entry.getKey(), entry.getValue())
            );

        UserAuthenticationData authenticationData = new UserAuthenticationData(
                AuthTimeDateConverter.authTimeToDate((Integer) refreshTokenClaims.get(AUTH_TIME)),
                authenticationMethodsAsSet(refreshTokenClaims),
                null,
                requestedScopes,
                rolesAsSet(userId),
                getUserAttributes(userId),
                nonce,
                grantType,
                generateUniqueTokenId());

        refreshTokenValue = tokenValidation.getJwt().getEncoded();
        CompositeToken compositeToken =
            createCompositeToken(
                    accessTokenId,
                    user.getId(),
                    user,
                    AuthTimeDateConverter.authTimeToDate((Integer) refreshTokenClaims.get(AUTH_TIME)),
                    getClientPermissions(client),
                    clientId,
                    audience /*request.createOAuth2Request(client).getResourceIds()*/,
                    refreshTokenValue,
                    additionalAuthorizationInfo,
                    additionalRootClaims,
                    new HashSet<>(),
                    revocableHashSignature,
                    false,
                    revocable,
                    authenticationData);

        CompositeExpiringOAuth2RefreshToken expiringRefreshToken = new CompositeExpiringOAuth2RefreshToken(refreshTokenValue, new Date(refreshTokenExpireDate), refreshTokenId);

        return persistRevocableToken(accessTokenId, compositeToken, expiringRefreshToken, clientId, user.getId(), opaque, revocable);
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

    private HashSet<String> authenticationMethodsAsSet(Map<String, Object> refreshTokenClaims) {
        ArrayList<String> authenticationMethods = (ArrayList<String>) refreshTokenClaims.get(AMR);
        return authenticationMethods == null ? Sets.newHashSet() : Sets.newHashSet(authenticationMethods);
    }

    private void checkForApproval(String userId,
                                  String clientId,
                                  Collection<String> requestedScopes,
                                  Collection<String> autoApprovedScopes) {
        if(autoApprovedScopes.containsAll(requestedScopes)) { return; }
        Set<String> approvedScopes = new HashSet<>(autoApprovedScopes);

        // Search through the users approvals for scopes that are requested, not
        // auto approved, not expired,
        // not DENIED and not approved more recently than when this access token
        // was issued.
        List<Approval> approvals = approvalStore.getApprovals(userId, clientId, IdentityZoneHolder.get().getId());
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
            Set<String> unapprovedScopes = new HashSet<>(requestedScopes);
            unapprovedScopes.removeAll(approvedScopes);
            throw new InvalidTokenException("Invalid token (some requested scopes are not approved): "
                            + unapprovedScopes);
        }
    }


    private CompositeToken createCompositeToken(String tokenId,
                                                String userId,
                                                UaaUser user,
                                                Date userAuthenticationTime,
                                                Collection<GrantedAuthority> clientScopes,
                                                String clientId,
                                                Set<String> resourceIds,
                                                String refreshToken,
                                                Map<String, String> additionalAuthorizationAttributes,
                                                Map<String, Object> additionalRootClaims,
                                                Set<String> responseTypes,
                                                String revocableHashSignature,
                                                boolean forceIdTokenCreation,
                                                boolean revocable,
                                                UserAuthenticationData userAuthenticationData) throws AuthenticationException {
        CompositeToken compositeToken = new CompositeToken(tokenId);
        compositeToken.setExpiration(accessTokenValidityResolver.resolve(clientId));
        compositeToken.setRefreshToken(refreshToken == null ? null : new DefaultOAuth2RefreshToken(refreshToken));

        Set<String> requestedScopes = userAuthenticationData.scopes;
        String grantType = userAuthenticationData.grantType;

        if (null == requestedScopes || requestedScopes.size() == 0) {
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

        compositeToken.setAdditionalInformation(info);

        String content;
        Map<String, ?> jwtAccessToken = createJWTAccessToken(
                compositeToken,
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
                additionalRootClaims);
        try {
            content = JsonUtils.writeValueAsString(jwtAccessToken);
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        String token = JwtHelper.encode(content, getActiveKeyInfo().getSigner()).getEncoded();
        compositeToken.setValue(token);
        if (shouldSendIdToken(clientScopes, requestedScopes, grantType, responseTypes, forceIdTokenCreation)) {
            String idTokenContent;
            try {
                idTokenContent = JsonUtils.writeValueAsString(idTokenCreator.create(clientId, userId, userAuthenticationData));
            } catch (RuntimeException | IdTokenCreationException e) {
                throw new IllegalStateException("Cannot convert id token to JSON");
            }
            String encodedIdTokenContent = JwtHelper.encode(idTokenContent, KeyInfo.getActiveKey().getSigner()).getEncoded();
            compositeToken.setIdTokenValue(encodedIdTokenContent);
        }

        publish(new TokenIssuedEvent(compositeToken, SecurityContextHolder.getContext().getAuthentication()));

        return compositeToken;
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

        boolean idTokenExplicitlyRequested = requestedScopes.contains("openid") && responseTypes.contains(CompositeToken.ID_TOKEN);
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
        claims.put(AZP, clientId);
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

        claims.put(IAT, timeService.getCurrentTimeMillis() / 1000);
        claims.put(EXP, token.getExpiration().getTime() / 1000);

        if (tokenEndpointBuilder.getTokenEndpoint() != null) {
            claims.put(ISS, tokenEndpointBuilder.getTokenEndpoint());
            claims.put(ZONE_ID,IdentityZoneHolder.get().getId());
        }

        // TODO: different values for audience in the AT and RT. Need to sync them up
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
            clientScopes = getClientPermissions(client);
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

        Map<String,Object> additionalRootClaims = null;
        if (uaaTokenEnhancer != null) {
            additionalRootClaims = new HashMap<>(uaaTokenEnhancer.enhance(emptyMap(), authentication));
        }

        CompositeExpiringOAuth2RefreshToken refreshToken = null;
        if(client.getAuthorizedGrantTypes().contains(GRANT_TYPE_REFRESH_TOKEN)){
            RefreshTokenRequestData refreshTokenRequestData = new RefreshTokenRequestData(
                oAuth2Request.getGrantType(),
                oAuth2Request.getScope(),
                authenticationMethods,
                oAuth2Request.getRequestParameters().get("authorities"),
                oAuth2Request.getResourceIds(),
                oAuth2Request.getClientId(),
                refreshTokenRevocable,
                userAuthenticationTime,
                authNContextClassRef,
                additionalRootClaims
            );
            refreshToken = refreshTokenCreator.createRefreshToken(user, refreshTokenRequestData, revocableHashSignature);
        }

        String clientId = oAuth2Request.getClientId();
        Set<String> userScopes = oAuth2Request.getScope();
        Map<String, String> requestParameters = oAuth2Request.getRequestParameters();
        String grantType = requestParameters.get("grant_type");

        Set<String> modifiableUserScopes = new LinkedHashSet<>(userScopes);

        Set<String> externalGroupsForIdToken = Sets.newHashSet();
        Map<String,List<String>> userAttributesForIdToken = Maps.newHashMap();
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

        UserAuthenticationData authenticationData = new UserAuthenticationData(userAuthenticationTime,
                authenticationMethods,
                authNContextClassRef,
                modifiableUserScopes,
                externalGroupsForIdToken,
                userAttributesForIdToken,
                nonce,
                grantType,
                tokenId);

        CompositeToken accessToken =
            createCompositeToken(
                tokenId,
                userId,
                user,
                userAuthenticationTime,
                clientScopes,
                    clientId,
                oAuth2Request.getResourceIds(),
                    refreshToken != null ? refreshToken.getValue() : null,
                    additionalAuthorizationAttributes,
                additionalRootClaims,
                responseTypes,
                revocableHashSignature,
                wasIdTokenRequestedThroughAuthCodeScopeParameter,
                    accessTokenRevocable,
                    authenticationData);

        return persistRevocableToken(tokenId, accessToken, refreshToken, clientId, userId, opaque, accessTokenRevocable);
    }

    private Collection<GrantedAuthority> getClientPermissions(ClientDetails client) {
        Collection<GrantedAuthority> clientScopes;
        clientScopes = new ArrayList<>();
        for(String scope : client.getScope()) {
            clientScopes.add(new XOAuthUserAuthority(scope));
        }
        return clientScopes;
    }

    private void validateRequiredUserGroups(UaaUser user, ClientDetails client) {
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

        CompositeToken result = new CompositeToken(opaque ? tokenId : token.getValue());
        result.setIdTokenValue(token.getIdTokenValue());
        result.setExpiration(token.getExpiration());
        result.setAdditionalInformation(token.getAdditionalInformation());
        result.setScope(token.getScope());
        result.setTokenType(token.getTokenType());
        result.setRefreshToken(refreshToken==null ? null : new DefaultOAuth2RefreshToken(refreshTokenOpaque ? refreshToken == null ? null : refreshToken.getJti() : refreshToken.getValue()));
        return result;
    }

    boolean opaqueTokenRequired(OAuth2Authentication authentication) {
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
    private Set<String> extractResponseTypes(OAuth2Authentication authentication) {
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

    private String getUserId(OAuth2Authentication authentication) {
        return Origin.getUserId(authentication.getUserAuthentication());
    }

    private String generateUniqueTokenId() {
        return UUID.randomUUID().toString().replace("-", "");
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
          tokenValidationService.validateToken(accessToken, true)
          .checkJti();

        Map<String, Object> claims = tokenValidation.getClaims();

        accessToken = tokenValidation.getJwt().getEncoded();

        // Check token expiry
        Long expiration = Long.valueOf(claims.get(EXP).toString());
        if (new Date(expiration * 1000L).before(new Date(timeService.getCurrentTimeMillis()))) {
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
                tokenValidationService.validateToken(accessToken, true).checkJti();

        Map<String, Object> claims = tokenValidation.getClaims();
        accessToken = tokenValidation.getJwt().getEncoded();

        // Expiry is verified by check_token
        CompositeToken token = new CompositeToken(accessToken);
        token.setTokenType(OAuth2AccessToken.BEARER_TYPE);
        token.setExpiration(new Date(Long.valueOf(claims.get(EXP).toString()) * 1000L));

        @SuppressWarnings("unchecked")
        ArrayList<String> scopes = (ArrayList<String>) claims.get(SCOPE);
        if (null != scopes && scopes.size() > 0) {
            token.setScope(new HashSet<>(scopes));
        }
        String clientId = claims.get(CID).toString();
        ClientDetails client = clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        String userId = claims.get(USER_ID).toString();
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

    public void setTokenEndpointBuilder(TokenEndpointBuilder tokenEndpointBuilder) {
        this.tokenEndpointBuilder = tokenEndpointBuilder;
    }

    public void setTimeService(TimeService timeService) {
        this.timeService = timeService;
    }
}
