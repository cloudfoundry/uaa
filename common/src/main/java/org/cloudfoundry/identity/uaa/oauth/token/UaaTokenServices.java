/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth.token;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.oauth.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ADDITIONAL_AZ_ATTR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUD;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUTHORITIES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUTH_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AZP;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXP;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.FAMILY_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GIVEN_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.IAT;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.NONCE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ORIGIN;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PHONE_NUMBER;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PROFILE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.REVOCATION_SIGNATURE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SCOPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ZONE_ID;


/**
 * This class provides token services for the UAA. It handles the production and
 * consumption of UAA tokens.
 *
 */
public class UaaTokenServices implements AuthorizationServerTokenServices, ResourceServerTokenServices,
                InitializingBean, ApplicationEventPublisherAware {

    private final Log logger = LogFactory.getLog(getClass());

    private UaaUserDatabase userDatabase = null;

    private ClientDetailsService clientDetailsService = null;

    private SignerProvider signerProvider = new SignerProvider();

    private String issuer = null;

    private String tokenEndpoint = null;

    private Set<String> defaultUserAuthorities = new HashSet<String>();

    private ApprovalStore approvalStore = null;

    private ApplicationEventPublisher applicationEventPublisher;
    private String host;

    private List<String> validIdTokenScopes = Arrays.asList("openid");
    private TokenPolicy tokenPolicy;

    private Set<String> excludedClaims = Collections.EMPTY_SET;
    
    private String typeHeader;
    
    public void setTypeHeader(String typeHeader) {
    	this.typeHeader = typeHeader;
    }

    public Set<String> getExcludedClaims() {
        return excludedClaims;
    }

    public void setExcludedClaims(Set<String> excludedClaims) {
        this.excludedClaims = excludedClaims;
    }

    public void setValidIdTokenScopes(List<String> validIdTokenScopes) {
        this.validIdTokenScopes = validIdTokenScopes;
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

        Map<String, Object> claims = getClaimsForToken(refreshTokenValue);

        // TODO: Should reuse the access token you get after the first
        // successful authentication.
        // You will get an invalid_grant error if your previous token has not
        // expired yet.
        // OAuth2RefreshToken refreshToken =
        // tokenStore.readRefreshToken(refreshTokenValue);
        // if (refreshToken == null) {
        // throw new InvalidGrantException("Invalid refresh token: " +
        // refreshTokenValue);
        // }

        String clientId = (String) claims.get(CID);
        if (clientId == null || !clientId.equals(request.getClientId())) {
            throw new InvalidGrantException("Wrong client for this refresh token: " + refreshTokenValue);
        }

        String userid = (String) claims.get(USER_ID);

        // TODO: Need to add a lookup by id so that the refresh token does not
        // need to contain a name
        UaaUser user = userDatabase.retrieveUserById(userid);
        ClientDetails client = clientDetailsService.loadClientByClientId(clientId);

        Integer refreshTokenIssuedAt = (Integer) claims.get(IAT);
        long refreshTokenIssueDate = refreshTokenIssuedAt.longValue() * 1000l;

        Integer refreshTokenExpiry = (Integer) claims.get(EXP);
        long refreshTokenExpireDate = refreshTokenExpiry.longValue() * 1000l;

        if (new Date(refreshTokenExpireDate).before(new Date())) {
            throw new InvalidTokenException("Invalid refresh token (expired): " + refreshTokenValue + " expired at "
                            + new Date(refreshTokenExpireDate));
        }

        @SuppressWarnings("unchecked")
        ArrayList<String> tokenScopes = (ArrayList<String>) claims.get(SCOPE);

        // default request scopes to what is in the refresh token
        Set<String> requestedScopes = request.getScope();
        if (requestedScopes.isEmpty()) {
            requestedScopes = new HashSet<String>(tokenScopes);
        }

        // The user may not request scopes that were not part of the refresh
        // token
        if (tokenScopes.isEmpty() || !tokenScopes.containsAll(requestedScopes)) {
            throw new InvalidScopeException("Unable to narrow the scope of the client authentication to "
                            + requestedScopes + ".", new HashSet<String>(tokenScopes));
        }

        // from this point on, we only care about the scopes requested, not what
        // is in the refresh token
        // ensure all requested scopes are approved: either automatically or
        // explicitly by the user
        String grantType = claims.get(GRANT_TYPE).toString();
        checkForApproval(userid, clientId, requestedScopes,
                        getAutoApprovedScopes(grantType, tokenScopes, client),
                        new Date(refreshTokenIssueDate));

        // if we have reached so far, issue an access token
        Integer validity = client.getAccessTokenValiditySeconds();

        String nonce = (String) claims.get(NONCE);

        @SuppressWarnings("unchecked")
        Map<String, String> additionalAuthorizationInfo = (Map<String, String>) claims.get(ADDITIONAL_AZ_ATTR);

        String revocableHashSignature = (String)claims.get(REVOCATION_SIGNATURE);
        if (StringUtils.hasText(revocableHashSignature)) {
            String newRevocableHashSignature = getRevocableTokenSignature(client, user);
            if (!revocableHashSignature.equals(newRevocableHashSignature)) {
                throw new TokenRevokedException(refreshTokenValue);
            }
        }

        Set<String> audience = new HashSet<>((ArrayList<String>)claims.get(AUD));

        int zoneAccessTokenValidity = getZoneAccessTokenValidity();

        OAuth2AccessToken accessToken =
            createAccessToken(
                user.getId(),
                user,
                claims.get(AUTH_TIME) != null ? new Date(((Long)claims.get(AUTH_TIME)) * 1000l) : null,
                validity != null ? validity.intValue() : zoneAccessTokenValidity,
                null,
                requestedScopes,
                clientId,
                audience /*request.createOAuth2Request(client).getResourceIds()*/,
                grantType,
                refreshTokenValue,
                nonce,
                additionalAuthorizationInfo,
                new HashSet<>(),
                revocableHashSignature,
                false,
                null,  //TODO populate response types
                null);

        return accessToken;
    }

    private int getZoneAccessTokenValidity() {
        IdentityZone zone = IdentityZoneHolder.get();
        IdentityZoneConfiguration definition = zone.getConfig();
        int zoneAccessTokenValidity = tokenPolicy.getAccessTokenValidity();
        if (definition != null) {
            zoneAccessTokenValidity = (definition.getTokenPolicy().getAccessTokenValidity() != -1) ? definition.getTokenPolicy().getAccessTokenValidity() : tokenPolicy.getAccessTokenValidity();
        }
        return zoneAccessTokenValidity;
    }

    private void checkForApproval(String userid,
                                  String clientId,
                                  Collection<String> requestedScopes,
                                  Collection<String> autoApprovedScopes,
                                  Date updateCutOff) {
        Set<String> approvedScopes = new HashSet<>(autoApprovedScopes);

        // Search through the users approvals for scopes that are requested, not
        // auto approved, not expired,
        // not DENIED and not approved more recently than when this access token
        // was issued.
        List<Approval> approvals = approvalStore.getApprovals(userid, clientId);
        for (Approval approval : approvals) {
            if (requestedScopes.contains(approval.getScope()) && approval.getStatus() == ApprovalStatus.APPROVED) {
                if (!approval.isCurrentlyActive()) {
                    logger.debug("Approval " + approval + " has expired. Need to re-approve.");
                    throw new InvalidTokenException("Invalid token (approvals expired)");
                }
                if (updateCutOff.before(approval.getLastUpdatedAt())) {
                    logger.debug("At least one approval " + approval + " was updated more recently at "
                                    + approval.getLastUpdatedAt() + " access token was issued at "
                                    + updateCutOff);
                    throw new InvalidTokenException("Invalid token (approvals updated): " + approval.getLastUpdatedAt());
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


    private OAuth2AccessToken createAccessToken(String userId,
                                                UaaUser user,
                                                Date userAuthenticationTime,
                                                int validitySeconds,
                                                Collection<GrantedAuthority> clientScopes,
                                                Set<String> requestedScopes,
                                                String clientId,
                                                Set<String> resourceIds,
                                                String grantType,
                                                String refreshToken,
                                                String nonce,
                                                Map<String, String> additionalAuthorizationAttributes,
                                                Set<String> responseTypes,
                                                String revocableHashSignature,
                                                boolean forceIdTokenCreation,
                                                Set<String> externalGroupsForIdToken,
                                                Map<String,List<String>> userAttributesForIdToken) throws AuthenticationException {
        String tokenId = UUID.randomUUID().toString();
        CompositeAccessToken accessToken = new CompositeAccessToken(tokenId);
        if (validitySeconds > 0) {
            accessToken.setExpiration(new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));
        }
        accessToken.setRefreshToken(refreshToken == null ? null : new DefaultOAuth2RefreshToken(refreshToken));

        if (null == requestedScopes || requestedScopes.size() == 0) {
            logger.debug("No scopes were granted");
            throw new InvalidTokenException("No scopes were granted");
        }

        accessToken.setScope(requestedScopes);

        Map<String, Object> info = new HashMap<String, Object>();
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
            refreshToken,
            revocableHashSignature
        );
        try {
            content = JsonUtils.writeValueAsString(jwtAccessToken);
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        String token = JwtHelper.encode(content, signerProvider.getSigner(), typeHeader).getEncoded();
        // This setter copies the value and returns. Don't change.
        accessToken.setValue(token);
        populateIdToken(accessToken, jwtAccessToken, requestedScopes, responseTypes, clientId, forceIdTokenCreation, externalGroupsForIdToken, user, userAttributesForIdToken);
        publish(new TokenIssuedEvent(accessToken, SecurityContextHolder.getContext().getAuthentication()));

        return accessToken;
    }

    private void populateIdToken(CompositeAccessToken token,
                                 Map<String, ?> accessTokenValues,
                                 Set<String> scopes,
                                 Set<String> responseTypes,
                                 String aud,
                                 boolean forceIdTokenCreation,
                                 Set<String> externalGroupsForIdToken,
                                 UaaUser user,
                                 Map<String,List<String>> userAttributesForIdToken) {
        if (forceIdTokenCreation || (scopes.contains("openid") && responseTypes.contains(CompositeAccessToken.ID_TOKEN))) {
            try {
                Map<String, Object> clone = new HashMap<>(accessTokenValues);
                clone.remove(AUTHORITIES);
                Set<String> idTokenScopes = new HashSet<>();
                for (String sc : scopes) {
                    if (validIdTokenScopes!=null && validIdTokenScopes.contains(sc)) {
                        idTokenScopes.add(sc);
                    }
                }
                clone.put(SCOPE, idTokenScopes);
                clone.put(AUD, new HashSet(Arrays.asList(aud)));

                if (scopes.contains(ROLES) && (externalGroupsForIdToken != null && !externalGroupsForIdToken.isEmpty())) {
                    clone.put(ROLES, externalGroupsForIdToken);
                }

                if (scopes.contains(USER_ATTRIBUTES) && userAttributesForIdToken!=null ) {
                    clone.put(USER_ATTRIBUTES, userAttributesForIdToken);
                }

                if(scopes.contains(PROFILE) && user != null) {
                    String givenName = user.getGivenName();
                    if(givenName != null) clone.put(GIVEN_NAME, givenName);

                    String familyName = user.getFamilyName();
                    if(familyName != null) clone.put(FAMILY_NAME, familyName);

                    String phoneNumber = user.getPhoneNumber();
                    if(phoneNumber != null) clone.put(PHONE_NUMBER, phoneNumber);
                }

                String content = JsonUtils.writeValueAsString(clone);
                String encoded = JwtHelper.encode(content, signerProvider.getSigner(), typeHeader).getEncoded();
                token.setIdTokenValue(encoded);
            } catch (JsonUtils.JsonUtilException e) {
                throw new IllegalStateException("Cannot convert ID token to JSON", e);
            }
        }
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
                                                String refreshToken,
                                                String revocableHashSignature) {

        Map<String, Object> response = new LinkedHashMap<String, Object>();

        response.put(JTI, token.getAdditionalInformation().get(JTI));
        response.putAll(token.getAdditionalInformation());

        response.put(SUB, userId);
        if (null != clientScopes) {
            response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(clientScopes));
        }

        response.put(OAuth2AccessToken.SCOPE, requestedScopes);
        response.put(CLIENT_ID, clientId);
        response.put(CID, clientId);
        response.put(AZP, clientId); //openId Connect

        if (null != grantType) {
            response.put(GRANT_TYPE, grantType);
        }
        if (!"client_credentials".equals(grantType)) {
            response.put(USER_ID, userId);
            if (user != null) {
                String origin = user.getOrigin();
                if (StringUtils.hasLength(origin)) {
                    response.put(ORIGIN, origin);
                }
                String username = user.getUsername();
                response.put(USER_NAME, username == null ? userId : username);
                String userEmail = user.getEmail();
                if (userEmail != null) {
                    response.put(EMAIL, userEmail);
                }
            }
            if (userAuthenticationTime!=null) {
                response.put(AUTH_TIME, userAuthenticationTime.getTime() / 1000);
            }
        }

        if (StringUtils.hasText(revocableHashSignature)) {
            response.put(REVOCATION_SIGNATURE, revocableHashSignature);
        }

        response.put(IAT, System.currentTimeMillis() / 1000);
        if (token.getExpiration() != null) {
            response.put(EXP, token.getExpiration().getTime() / 1000);
        }

        if (getTokenEndpoint() != null) {
            response.put(ISS, getTokenEndpoint());
            response.put(ZONE_ID,IdentityZoneHolder.get().getId());
        }

        // TODO: different values for audience in the AT and RT. Need to sync
        // them up
        response.put(AUD, resourceIds);

        for (String excludedClaim : getExcludedClaims()) {
            response.remove(excludedClaim);
        }

        return response;
    }

    @Override
    public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {

        String userId;
        Date userAuthenticationTime = null;
        UaaUser user = null;
        boolean wasIdTokenRequestedThroughAuthCodeScopeParameter = false;
        Collection<GrantedAuthority> clientScopes = null;
        // Clients should really by different kinds of users
        if (authentication.isClientOnly()) {
            ClientDetails client = clientDetailsService.loadClientByClientId(authentication.getName());
            userId = client.getClientId();
            clientScopes = client.getAuthorities();
        } else {
            userId = getUserId(authentication);
            user = userDatabase.retrieveUserById(userId);
            if (authentication.getUserAuthentication() instanceof UaaAuthentication) {
                userAuthenticationTime = new Date(((UaaAuthentication)authentication.getUserAuthentication()).getAuthenticatedTime());
            }
        }

        ClientDetails client = clientDetailsService.loadClientByClientId(authentication.getOAuth2Request().getClientId());
        String revocableHashSignature = getRevocableTokenSignature(client, user);

        OAuth2RefreshToken refreshToken = createRefreshToken(authentication, revocableHashSignature);


        String clientId = authentication.getOAuth2Request().getClientId();
        Set<String> userScopes = authentication.getOAuth2Request().getScope();
        String grantType = authentication.getOAuth2Request().getRequestParameters().get("grant_type");

        Set<String> modifiableUserScopes = new LinkedHashSet<String>();
        modifiableUserScopes.addAll(userScopes);
        String externalScopes = authentication.getOAuth2Request().getRequestParameters()
                        .get("external_scopes");
        if (null != externalScopes && StringUtils.hasLength(externalScopes)) {
            modifiableUserScopes.addAll(OAuth2Utils.parseParameterList(externalScopes));
        }

        Set<String> externalGroupsForIdToken = Collections.EMPTY_SET;
        Map<String,List<String>> userAttributesForIdToken = Collections.EMPTY_MAP;
        if (authentication.getUserAuthentication() instanceof UaaAuthentication) {
            externalGroupsForIdToken = ((UaaAuthentication)authentication.getUserAuthentication()).getExternalGroups();
            userAttributesForIdToken = ((UaaAuthentication)authentication.getUserAuthentication()).getUserAttributes();
        }

        String nonce = authentication.getOAuth2Request().getRequestParameters().get(NONCE);

        Map<String, String> additionalAuthorizationAttributes =
            getAdditionalAuthorizationAttributes(
                authentication.getOAuth2Request().getRequestParameters().get("authorities")
            );

        if ("authorization_code".equals(authentication.getOAuth2Request().getRequestParameters().get(OAuth2Utils.GRANT_TYPE)) &&
            "code".equals(authentication.getOAuth2Request().getRequestParameters().get(OAuth2Utils.RESPONSE_TYPE)) &&
            authentication.getOAuth2Request().getRequestParameters().get(OAuth2Utils.SCOPE)!=null &&
            authentication.getOAuth2Request().getRequestParameters().get(OAuth2Utils.SCOPE).contains("openid")) {
            wasIdTokenRequestedThroughAuthCodeScopeParameter = true;
        }

        int zoneAccessTokenValidity = getZoneAccessTokenValidity();

        Integer validity = client.getAccessTokenValiditySeconds();
        Set<String> responseTypes = extractResponseTypes(authentication);
        OAuth2AccessToken accessToken =
            createAccessToken(
                userId,
                user,
                userAuthenticationTime,
                validity != null ? validity.intValue() : zoneAccessTokenValidity,
                clientScopes,
                modifiableUserScopes,
                clientId,
                authentication.getOAuth2Request().getResourceIds(),
                grantType,
                refreshToken != null ? refreshToken.getValue() : null,
                nonce,
                additionalAuthorizationAttributes,
                responseTypes,
                revocableHashSignature,
                wasIdTokenRequestedThroughAuthCodeScopeParameter,
                externalGroupsForIdToken,
                userAttributesForIdToken);

        return accessToken;
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

    /**
     * This method searches the authorities in the request for
     * additionalAuthorizationAttributes
     * and returns a map of these attributes that will later be added to the
     * token
     *
     * @param authoritiesJson
     * @return
     */
    private Map<String, String> getAdditionalAuthorizationAttributes(String authoritiesJson) {
        if (StringUtils.hasLength(authoritiesJson)) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> authorities = JsonUtils.readValue(authoritiesJson, new TypeReference<Map<String, Object>>() {});
                @SuppressWarnings("unchecked")
                Map<String, String> additionalAuthorizationAttributes =
                    (Map<String, String>) authorities.get("az_attr");

                return additionalAuthorizationAttributes;
            } catch (Throwable t) {
                logger.error("Unable to read additionalAuthorizationAttributes", t);
            }
        }

        return null;
    }

    private ExpiringOAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication, String revocableHashSignature) {

        String grantType = authentication.getOAuth2Request().getRequestParameters().get("grant_type");
        if (!isRefreshTokenSupported(grantType)) {
            return null;
        }

        Map<String, String> additionalAuthorizationAttributes = getAdditionalAuthorizationAttributes(authentication
            .getOAuth2Request().getRequestParameters().get("authorities"));

        int validitySeconds = getRefreshTokenValiditySeconds(authentication.getOAuth2Request());
        ExpiringOAuth2RefreshToken token = new DefaultExpiringOAuth2RefreshToken(UUID.randomUUID().toString(),
                        new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));

        String userId = getUserId(authentication);

        UaaUser user = userDatabase.retrieveUserById(userId);

        String content;
        try {
            content = JsonUtils.writeValueAsString(
                createJWTRefreshToken(
                    token, user, authentication.getOAuth2Request().getScope(),
                    authentication.getOAuth2Request().getClientId(),
                    grantType, additionalAuthorizationAttributes,authentication.getOAuth2Request().getResourceIds(),
                    revocableHashSignature
                )
            );
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        String jwtToken = JwtHelper.encode(content, signerProvider.getSigner(), typeHeader).getEncoded();

        ExpiringOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken(jwtToken, token.getExpiration());

        return refreshToken;
    }

    protected String getRevocableTokenSignature(ClientDetails client, UaaUser user) {
        String[] salts = new String[] {
            client.getClientId(),
            client.getClientSecret(),
            (String)client.getAdditionalInformation().get(ClientConstants.TOKEN_SALT),
            user == null ? null : user.getId(),
            user == null ? null : user.getPassword(),
            user == null ? null : user.getSalt(),
            user == null ? null : user.getEmail(),
            user == null ? null : user.getUsername(),
        };
        List<String> saltlist = new LinkedList<>();
        for (String s : salts) {
            if (s!=null) {
                saltlist.add(s);
            }
        }
        return signerProvider.getRevocationHash(saltlist);
    }

    protected String getUserId(OAuth2Authentication authentication) {
        return Origin.getUserId(authentication.getUserAuthentication());
    }

    private Map<String, ?> createJWTRefreshToken(
        OAuth2RefreshToken token,
        UaaUser user,
        Set<String> scopes,
        String clientId,
        String grantType,
        Map<String, String> additionalAuthorizationAttributes,
        Set<String> resourceIds,
        String revocableSignature) {

        Map<String, Object> response = new LinkedHashMap<String, Object>();

        response.put(JTI, UUID.randomUUID().toString()+"-r"); //-r for refresh token
        response.put(SUB, user.getId());
        response.put(SCOPE, scopes);
        if (null != additionalAuthorizationAttributes) {
            response.put(ADDITIONAL_AZ_ATTR, additionalAuthorizationAttributes);
        }

        response.put(IAT, System.currentTimeMillis() / 1000);
        if (((ExpiringOAuth2RefreshToken) token).getExpiration() != null) {
            response.put(EXP, ((ExpiringOAuth2RefreshToken) token).getExpiration().getTime() / 1000);
        }

        response.put(CID, clientId);
        response.put(CLIENT_ID, clientId);
        if (getTokenEndpoint() != null) {
            response.put(ISS, getTokenEndpoint());
            response.put(ZONE_ID,IdentityZoneHolder.get().getId());
        }

        if (null != grantType) {
            response.put(GRANT_TYPE, grantType);
        }
        if (!"client_credentials".equals(grantType)) {
            response.put(USER_NAME, user.getUsername());
            response.put(ORIGIN, user.getOrigin());
            response.put(USER_ID, user.getId());
        }

        if (StringUtils.hasText(revocableSignature)) {
            response.put(REVOCATION_SIGNATURE, revocableSignature);
        }

        response.put(AUD, resourceIds);

        return response;
    }

    /**
     * Check the current authorization request to indicate whether a refresh
     * token should be issued or not.
     *
     * @param grantType the current grant type
     * @return boolean to indicate if refresh token is supported
     */
    protected boolean isRefreshTokenSupported(String grantType) {
        return "authorization_code".equals(grantType) || "password".equals(grantType)
                        || "refresh_token".equals(grantType);
    }

    /**
     * The refresh token validity period in seconds
     *
     * @param authorizationRequest the current authorization request
     * @return the refresh token validity period in seconds
     */
    protected int getRefreshTokenValiditySeconds(OAuth2Request authorizationRequest) {
        ClientDetails client = clientDetailsService.loadClientByClientId(authorizationRequest.getClientId());
        Integer validity = client.getRefreshTokenValiditySeconds();
        if (validity != null) {
            return validity;
        }

        IdentityZone zone = IdentityZoneHolder.get();
        IdentityZoneConfiguration definition = zone.getConfig();
        int zoneRefreshTokenValidity = tokenPolicy.getRefreshTokenValidity();
        if (definition != null) {
            zoneRefreshTokenValidity = (definition.getTokenPolicy().getRefreshTokenValidity() != -1) ? definition.getTokenPolicy().getRefreshTokenValidity() : tokenPolicy.getRefreshTokenValidity();
        }

        return zoneRefreshTokenValidity;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(clientDetailsService, "clientDetailsService must be set");
        Assert.notNull(issuer, "issuer must be set");
        Assert.notNull(approvalStore, "approvalStore must be set");
        URI uri = new URI(issuer);
        host = uri.getHost();
    }

    public void setUserDatabase(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    private void validateClient(String clientId) throws AuthenticationException {
        if (clientId!=null) {
            try {
                clientDetailsService.loadClientByClientId(clientId);
            } catch (NoSuchClientException x) {
                throw new OAuth2AccessDeniedException("Invalid client:"+clientId);
            } catch (ClientRegistrationException x) {
                throw new OAuth2AccessDeniedException("Invalid client:"+clientId);
            } catch (InvalidClientException x) {
                throw new OAuth2AccessDeniedException("Invalid client:"+clientId);
            }
        }
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException {
        Map<String, Object> claims = getClaimsForToken(accessToken);

        // Check token expiry
        Integer expiration = (Integer) claims.get(EXP);
        if (expiration != null && new Date(expiration * 1000l).before(new Date())) {
            throw new InvalidTokenException("Invalid access token (expired): " + accessToken + " expired at "
                            + new Date(expiration * 1000l));
        }

        // Check client ID is valid
        validateClient((String) claims.get(CLIENT_ID));
        validateClient((String)claims.get(CID));


        @SuppressWarnings("unchecked")
        ArrayList<String> scopes = (ArrayList<String>) claims.get(SCOPE);

        AuthorizationRequest authorizationRequest = new AuthorizationRequest((String) claims.get(CLIENT_ID),
                        scopes);

        ArrayList<String> rids = (ArrayList<String>) claims.get(AUD);
        //TODO - Fix null resource IDs for a client_credentials request to /oauth/token
        Set<String> resourceIds = Collections.unmodifiableSet(rids==null?new HashSet<String>():new HashSet<>(rids));
        authorizationRequest.setResourceIds(resourceIds);

        authorizationRequest.setApproved(true);

        Collection<? extends GrantedAuthority> authorities = AuthorityUtils
                        .commaSeparatedStringToAuthorityList(StringUtils
                                        .collectionToCommaDelimitedString(defaultUserAuthorities));
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
        // Is this a user token?
        if (claims.containsKey(EMAIL)) {
            UaaUser user = userDatabase.retrieveUserById((String)claims.get(USER_ID));
            UaaPrincipal principal = new UaaPrincipal(user);
            userAuthentication = new UaaAuthentication(principal, UaaAuthority.USER_AUTHORITIES, null);
        }
        else {
            authorizationRequest.setAuthorities(authorities);
        }

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        authentication.setAuthenticated(true);
        return authentication;
    }

    /**
     * This method is implemented to support older API calls that assume the
     * presence of a token store
     */
    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        Map<String, Object> claims = getClaimsForToken(accessToken);

        // Expiry is verified by check_token
        CompositeAccessToken token = new CompositeAccessToken(accessToken);
        token.setTokenType(OAuth2AccessToken.BEARER_TYPE);
        Integer exp = (Integer) claims.get(EXP);
        if (null != exp) {
            token.setExpiration(new Date(exp.longValue() * 1000l));
        }

        @SuppressWarnings("unchecked")
        ArrayList<String> scopes = (ArrayList<String>) claims.get(SCOPE);
        if (null != scopes && scopes.size() > 0) {
            token.setScope(new HashSet<String>(scopes));
        }
        String clientId = (String) claims.get(CID);
        ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
        String email = (String) claims.get(EMAIL);

        // Only check user access tokens
        if (null != email) {
            String userId = (String)claims.get(USER_ID);

            UaaUser user;
            try {
                user = userDatabase.retrieveUserById(userId);
            } catch (UsernameNotFoundException e) {
                throw new InvalidTokenException("Invalid access token (user ID not found): " + userId);
            }

            Integer accessTokenIssuedAt = (Integer) claims.get(IAT);
            long accessTokenIssueDate = accessTokenIssuedAt.longValue() * 1000l;
            // Check approvals to make sure they're all valid, approved and not
            // more recent
            // than the token itself

            validateUserScopes(scopes, user.getAuthorities());
            validateClientScopes(scopes, client.getScope());
            @SuppressWarnings("unchecked")
            ArrayList<String> tokenScopes = (ArrayList<String>) claims.get(SCOPE);
            Set<String> autoApprovedScopes = getAutoApprovedScopes(claims.get(GRANT_TYPE), tokenScopes, client);
            if (autoApprovedScopes.containsAll(tokenScopes)) {
                return token;
            }
            checkForApproval(userId, clientId, tokenScopes, autoApprovedScopes, new Date(accessTokenIssueDate));
        } else {
            validateClientAuthorities(scopes, (List<? extends GrantedAuthority>) client.getAuthorities());
        }

        return token;
    }

    private void validateClientAuthorities(ArrayList<String> scopes, List<? extends GrantedAuthority> authorities) {
        validateAuthorities(scopes, authorities);
    }

    private void validateUserScopes(ArrayList<String> scopes, List<? extends GrantedAuthority> authorities) {
        validateAuthorities(scopes, authorities);
    }

    private void validateAuthorities(ArrayList<String> scopes, List<? extends GrantedAuthority> authorities) {
        if (authorities != null) {
            List<String> authoritiesValue = authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
            scopes.stream().forEach(s -> {
                if(!authoritiesValue.contains(s)) {
                    throw new InvalidTokenException("Invalid token (scope " + s +" has been revoked)");
                }
            });
        } else {
            throw new InvalidTokenException("Invalid token (all scopes have been revoked)");
        }
    }

    private void validateClientScopes(ArrayList<String> scopes, Set<String> authorities) {
        if (authorities != null) {
            ArrayList<String> a = new ArrayList<>();
            a.addAll(authorities);
            Set<Pattern> wildcards = UaaStringUtils.constructWildcards(authorities);
            scopes.stream().forEach(s -> {
                if(!authorities.contains(s) && !UaaStringUtils.matches(wildcards, s)) {
                    throw new InvalidTokenException("Invalid token (scope " + s +" has been revoked)");
                }
            });
        } else {
            throw new InvalidTokenException("Invalid token (all scopes have been revoked)");
        }
    }

    private Set<String> getAutoApprovedScopes(Object grantType, Collection<String> tokenScopes, ClientDetails client) {
        // ALL requested scopes are considered auto-approved for password grant
        if (grantType != null && "password".equals(grantType.toString())) {
            return new HashSet<String>(tokenScopes);
        }

        // start with scopes listed as autoapprove in client config
        Object autoApproved = client.getAdditionalInformation().get(ClientConstants.AUTO_APPROVE);
        Set<String> autoApprovedScopes = new HashSet<>();
        if (autoApproved instanceof Collection<?>) {
            @SuppressWarnings("unchecked")
            Collection<? extends String> approvedScopes = (Collection<? extends String>) autoApproved;
            autoApprovedScopes.addAll(approvedScopes);
        } else if (autoApproved instanceof Boolean && (Boolean) autoApproved || "true".equals(autoApproved)) {
            autoApprovedScopes.addAll(client.getScope());
        }
        if (client instanceof BaseClientDetails && ((BaseClientDetails)client).getAutoApproveScopes()!=null) {
            autoApprovedScopes.addAll(((BaseClientDetails)client).getAutoApproveScopes());
        }

        // retain only the requested scopes
        return UaaTokenUtils.instance().retainAutoApprovedScopes(tokenScopes, autoApprovedScopes);
    }

    private Map<String, Object> getClaimsForToken(String token) {
        Jwt tokenJwt = null;
        try {
            tokenJwt = JwtHelper.decodeAndVerify(token, signerProvider.getVerifier());
        } catch (Throwable t) {
            logger.debug("Invalid token (could not decode)", t);
            throw new InvalidTokenException("Invalid token (could not decode): " + token);
        }

        Map<String, Object> claims = null;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot read token claims", e);
        }

        if (getTokenEndpoint()!=null && !getTokenEndpoint().equals(claims.get(ISS))) {
            throw new InvalidTokenException("Invalid issuer for token:"+claims.get(ISS));
        }

        String signature = (String)claims.get(REVOCATION_SIGNATURE);
        if (signature!=null) { //this ensures backwards compatibility during upgrade
            String clientId = (String) claims.get(CID);
            String userId = (String) claims.get(USER_ID);
            UaaUser user = null;
            ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
            try {
                user = userDatabase.retrieveUserById(userId);
            } catch (UsernameNotFoundException x) {
            }
            if (signature != null && !signature.equals(getRevocableTokenSignature(client, user))) {
                throw new TokenRevokedException(token);
            }
        }

        return claims;
    }

    /**
     * This method is implemented only to support older API calls that assume
     * the presence of a token store
     */
    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        return null;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getTokenEndpoint() {
        if (issuer==null) {
            return null;
        } else {
            String hostToUse = host;
            if (StringUtils.hasText(IdentityZoneHolder.get().getSubdomain())) {
                hostToUse = IdentityZoneHolder.get().getSubdomain() + "." + host;
            }
            return UriComponentsBuilder.fromUriString(issuer).host(hostToUse).pathSegment("oauth/token").build().toUriString();
        }
    }

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setSignerProvider(SignerProvider signerProvider) {
        this.signerProvider = signerProvider;
    }

    public void setDefaultUserAuthorities(Set<String> defaultUserAuthorities) {
        this.defaultUserAuthorities = defaultUserAuthorities;
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
}
