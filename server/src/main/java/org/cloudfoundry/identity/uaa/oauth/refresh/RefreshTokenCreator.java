package org.cloudfoundry.identity.uaa.oauth.refresh;

import com.google.common.collect.Maps;
import org.cloudfoundry.identity.uaa.oauth.*;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InsufficientScopeException;

import java.util.*;

import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.openid.IdToken.ACR_VALUES_KEY;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.*;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.*;
import static org.springframework.util.StringUtils.hasText;

public class RefreshTokenCreator {
    private boolean isRestrictRefreshGrant;
    private final TokenValidityResolver refreshTokenValidityResolver;
    private final TokenEndpointBuilder tokenEndpointBuilder;
    private TimeService timeService;
    private final KeyInfoService keyInfoService;

    private static final String UAA_REFRESH_TOKEN = "uaa.offline_token";

    public RefreshTokenCreator(boolean isRestrictRefreshGrant,
            TokenValidityResolver refreshTokenValidityResolver,
            TokenEndpointBuilder tokenEndpointBuilder,
            TimeService timeService,
            KeyInfoService keyInfoService) {
        this.isRestrictRefreshGrant = isRestrictRefreshGrant;
        this.refreshTokenValidityResolver = refreshTokenValidityResolver;
        this.tokenEndpointBuilder = tokenEndpointBuilder;
        this.timeService = timeService;
        this.keyInfoService = keyInfoService;
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

        String jwtToken = buildJwtToken(user,
                tokenRequestData,
                revocableHashSignature,
                grantType,
                additionalAuthorizationAttributes,
                expirationDate,
                tokenId);

        return new CompositeExpiringOAuth2RefreshToken(jwtToken, expirationDate, tokenId);
    }

    private String buildJwtToken(UaaUser user,
            RefreshTokenRequestData tokenRequestData,
            String revocableHashSignature,
            String grantType,
            Map<String, String> additionalAuthorizationAttributes,
            Date expirationDate,
            String tokenId) {

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put(JTI, tokenId);
        claims.put(SUB, user.getId());
        claims.put(IAT, timeService.getCurrentTimeMillis() / 1000);
        claims.put(EXPIRY_IN_SECONDS, expirationDate.getTime() / 1000);
        claims.put(CID, tokenRequestData.clientId);
        claims.put(CLIENT_ID, tokenRequestData.clientId);
        claims.put(ISS, tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        claims.put(ZONE_ID, IdentityZoneHolder.get().getId());
        claims.put(AUD, UaaStringUtils.getValuesOrDefaultValue(tokenRequestData.resourceIds, tokenRequestData.clientId));
        claims.put(GRANTED_SCOPES, tokenRequestData.scopes);

        if (null != tokenRequestData.authenticationMethods && !tokenRequestData.authenticationMethods.isEmpty()) {
            claims.put(AMR, tokenRequestData.authenticationMethods);
        }
        if (null != tokenRequestData.authTime) {
            claims.put(AUTH_TIME, AuthTimeDateConverter.dateToAuthTime(tokenRequestData.authTime));
        }
        if (null != tokenRequestData.acr && !tokenRequestData.acr.isEmpty()) {
            HashMap<Object, Object> acrMap = Maps.newHashMap();
            acrMap.put(ACR_VALUES_KEY, tokenRequestData.acr);
            claims.put(ACR, acrMap);
        }
        if (null != additionalAuthorizationAttributes) {
            claims.put(ADDITIONAL_AZ_ATTR, additionalAuthorizationAttributes);
        }
        if (null != tokenRequestData.externalAttributes) {
            claims.putAll(tokenRequestData.externalAttributes);
        }
        if (null != grantType) {
            claims.put(GRANT_TYPE, grantType);
        }
        if (null != user) {
            claims.put(USER_NAME, user.getUsername());
            claims.put(ORIGIN, user.getOrigin());
            claims.put(USER_ID, user.getId());
        }

        if (tokenRequestData.revocable) {
            claims.put(REVOCABLE, true);
        }

        if (hasText(revocableHashSignature)) {
            claims.put(REVOCATION_SIGNATURE, revocableHashSignature);
        }

        return JwtHelper.encode(claims, getActiveKeyInfo()).getEncoded();
    }

    private KeyInfo getActiveKeyInfo() {
        return ofNullable(keyInfoService.getActiveKey())
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
            return GRANT_TYPE_AUTHORIZATION_CODE.equals(grantType) ||
                    GRANT_TYPE_PASSWORD.equals(grantType) ||
                    GRANT_TYPE_USER_TOKEN.equals(grantType) ||
                    GRANT_TYPE_REFRESH_TOKEN.equals(grantType) ||
                    GRANT_TYPE_SAML2_BEARER.equals(grantType) ||
                    GRANT_TYPE_JWT_BEARER.equals(grantType) ||
                    GRANT_TYPE_TOKEN_EXCHANGE.equals(grantType);
        } else {
            return scope.contains(UAA_REFRESH_TOKEN);
        }
    }

    public void ensureRefreshTokenCreationNotRestricted(ArrayList<String> tokenScopes) {
        if (isRestrictRefreshGrant && !tokenScopes.contains(UAA_REFRESH_TOKEN)) {
            throw new InsufficientScopeException("Expected scope %s is missing".formatted(UAA_REFRESH_TOKEN));
        }
    }

    public void setRestrictRefreshGrant(boolean isRestrictRefreshGrant) {
        this.isRestrictRefreshGrant = isRestrictRefreshGrant;
    }

    public void setTimeService(TimeService timeService) {
        this.timeService = timeService;
    }

    public boolean shouldRotateRefreshTokens(String clientAuth) {
        return getActiveTokenPolicy().isRefreshTokenRotate() || CLIENT_AUTH_NONE.equals(clientAuth);
    }

    private Map<String, Object> getRefreshedTokenMap(Claims claims) {
        claims.setJti(UUID.randomUUID().toString().replace("-", "") + REFRESH_TOKEN_SUFFIX);
        return claims.getClaimMap();
    }

    public String createRefreshTokenValue(JwtTokenSignedByThisUAA jwtToken, Claims claims, String clientAuth) {
        String refreshTokenValue;
        if (shouldRotateRefreshTokens(clientAuth)) {
            refreshTokenValue = JwtHelper.encode(getRefreshedTokenMap(claims), getActiveKeyInfo()).getEncoded();
        } else {
            refreshTokenValue = jwtToken.getJwt().getEncoded();
        }
        return refreshTokenValue;
    }

    private TokenPolicy getActiveTokenPolicy() {
        return IdentityZoneHolder.get().getConfig().getTokenPolicy();
    }
}
