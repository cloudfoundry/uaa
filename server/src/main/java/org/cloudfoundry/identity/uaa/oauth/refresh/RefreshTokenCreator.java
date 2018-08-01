package org.cloudfoundry.identity.uaa.oauth.refresh;

import com.google.common.collect.Maps;
import org.cloudfoundry.identity.uaa.oauth.*;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;

import java.util.*;

import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.*;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.*;
import static org.springframework.util.StringUtils.hasText;

public class RefreshTokenCreator {
    private boolean isRestrictRefreshGrant;
    private final TokenValidityResolver refreshTokenValidityResolver;
    private final TokenEndpointBuilder tokenEndpointBuilder;
    private TimeService timeService;

    private final String UAA_REFRESH_TOKEN = "uaa.offline_token";

    public RefreshTokenCreator(boolean isRestrictRefreshGrant,
                               TokenValidityResolver refreshTokenValidityResolver,
                               TokenEndpointBuilder tokenEndpointBuilder,
                               TimeService timeService) {
        this.isRestrictRefreshGrant = isRestrictRefreshGrant;
        this.refreshTokenValidityResolver = refreshTokenValidityResolver;
        this.tokenEndpointBuilder = tokenEndpointBuilder;
        this.timeService = timeService;
    }

    public CompositeExpiringOAuth2RefreshToken createRefreshToken(UaaUser user,
                                                         RefreshTokenRequestData tokenRequestData,
                                                         String revocableHashSignature) {

        String grantType = tokenRequestData.grantType;
        Set<String> scope = tokenRequestData.scopes;
        if (!isRefreshTokenSupported(grantType, scope)) {
            return null;
        }

        Map<String, String> additionalAuthorizationAttributes = new AuthorizationAttributesParser().getAdditionalAuthorizationAttributes(tokenRequestData.authorities);

        Date expirationDate = refreshTokenValidityResolver.resolve(tokenRequestData.clientId);
        String tokenId = UUID.randomUUID().toString().replace("-", "") + REFRESH_TOKEN_SUFFIX;

        String jwtToken = buildJwtToken(user, tokenRequestData, revocableHashSignature, grantType, additionalAuthorizationAttributes, expirationDate, tokenId);

        return new CompositeExpiringOAuth2RefreshToken(jwtToken, expirationDate, tokenId);
    }

    private String buildJwtToken(UaaUser user, RefreshTokenRequestData tokenRequestData, String revocableHashSignature, String grantType, Map<String, String> additionalAuthorizationAttributes, Date expirationDate, String tokenId) {
        String content;
        try {
            Map<String, Object> response = new LinkedHashMap<>();

            response.put(JTI, tokenId);
            response.put(SUB, user.getId());
            response.put(IAT, timeService.getCurrentTimeMillis() / 1000);
            response.put(EXP, expirationDate.getTime() / 1000);
            response.put(CID, tokenRequestData.clientId);
            response.put(CLIENT_ID, tokenRequestData.clientId);
            response.put(ISS, tokenEndpointBuilder.getTokenEndpoint());
            response.put(ZONE_ID, IdentityZoneHolder.get().getId());
            response.put(AUD, tokenRequestData.resourceIds);
            response.put(GRANTED_SCOPES, tokenRequestData.scopes);

            if (null != tokenRequestData.authenticationMethods && !tokenRequestData.authenticationMethods.isEmpty()) {
                response.put(AMR, tokenRequestData.authenticationMethods);
            }
            if (null != tokenRequestData.authTime) {
                response.put(AUTH_TIME, AuthTimeDateConverter.dateToAuthTime(tokenRequestData.authTime));
            }
            if (null != tokenRequestData.acr && !tokenRequestData.acr.isEmpty()) {
                HashMap<Object, Object> acrMap = Maps.newHashMap();
                acrMap.put("values", tokenRequestData.acr);
                response.put(ACR, acrMap);
            }
            if (null != additionalAuthorizationAttributes) {
                response.put(ADDITIONAL_AZ_ATTR, additionalAuthorizationAttributes);
            }
            if (null != tokenRequestData.externalAttributes) {
                response.putAll(tokenRequestData.externalAttributes);
            }
            if (null != grantType) {
                response.put(GRANT_TYPE, grantType);
            }
            if (null != user) {
                response.put(USER_NAME, user.getUsername());
                response.put(ORIGIN, user.getOrigin());
                response.put(USER_ID, user.getId());
            }

            if (tokenRequestData.revocable) {
                response.put(ClaimConstants.REVOCABLE, true);
            }

            if (hasText(revocableHashSignature)) {
                response.put(REVOCATION_SIGNATURE, revocableHashSignature);
            }

            content = JsonUtils.writeValueAsString(response);
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        return JwtHelper.encode(content, getActiveKeyInfo().getSigner()).getEncoded();
    }

    private KeyInfo getActiveKeyInfo() {
        return ofNullable(KeyInfo.getActiveKey())
            .orElseThrow(() -> new InternalAuthenticationServiceException("Unable to sign token, misconfigured JWT signing keys"));
    }

    /**
     * Check the current authorization request to indicate whether a refresh
     * token should be issued or not.
     *
     * @param grantType the current grant type
     * @param scope
     * @return boolean to indicate if refresh token is supported
     */
    protected boolean isRefreshTokenSupported(String grantType, Set<String> scope) {
        if (!isRestrictRefreshGrant) {
            return "authorization_code".equals(grantType) ||
                "password".equals(grantType) ||
                GRANT_TYPE_USER_TOKEN.equals(grantType) ||
                GRANT_TYPE_REFRESH_TOKEN.equals(grantType) ||
                GRANT_TYPE_SAML2_BEARER.equals(grantType);
        } else {
            return scope.contains(UAA_REFRESH_TOKEN);
        }
    }

    public void ensureRefreshTokenCreationNotRestricted(ArrayList<String> tokenScopes) {
        if (isRestrictRefreshGrant && !tokenScopes.contains(UAA_REFRESH_TOKEN)) {
            throw new InsufficientScopeException(String.format("Expected scope %s is missing", UAA_REFRESH_TOKEN));
        }
    }

    public void setRestrictRefreshGrant(boolean isRestrictRefreshGrant) {
        this.isRestrictRefreshGrant = isRestrictRefreshGrant;
    }

    public void setTimeService(TimeService timeService) {
        this.timeService = timeService;
    }
}
