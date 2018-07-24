package org.cloudfoundry.identity.uaa.oauth.refresh;

import org.cloudfoundry.identity.uaa.oauth.AuthorizationAttributesParser;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.UaaTokenServices.UAA_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ADDITIONAL_AZ_ATTR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUD;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXP;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANTED_SCOPES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.IAT;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ORIGIN;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.REVOCATION_SIGNATURE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ZONE_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.springframework.util.StringUtils.hasText;

public class RefreshTokenCreator {
    private boolean isRestrictRefreshGrant;
    private TokenValidityResolver refreshTokenValidityResolver;
    private String issuer;

    public RefreshTokenCreator(boolean isRestrictRefreshGrant,
                               TokenValidityResolver refreshTokenValidityResolver,
                               String issuer) {
        this.isRestrictRefreshGrant = isRestrictRefreshGrant;
        this.refreshTokenValidityResolver = refreshTokenValidityResolver;
        this.issuer = issuer;
    }

    public ExpiringOAuth2RefreshToken createRefreshToken(UaaUser user,
                                                          String tokenId,
                                                          OAuth2Authentication authentication,
                                                          String revocableHashSignature,
                                                          boolean revocable,
                                                          Map<String,Object> externalAttributes) {

        String grantType = authentication.getOAuth2Request().getRequestParameters().get("grant_type");
        Set<String> scope = authentication.getOAuth2Request().getScope();
        if (!isRefreshTokenSupported(grantType, scope)) {
            return null;
        }

        Map<String, String> additionalAuthorizationAttributes = new AuthorizationAttributesParser().getAdditionalAuthorizationAttributes(authentication
            .getOAuth2Request().getRequestParameters().get("authorities"));

        Date validitySeconds = refreshTokenValidityResolver.resolve(authentication.getOAuth2Request().getClientId());
        ExpiringOAuth2RefreshToken token = new DefaultExpiringOAuth2RefreshToken(tokenId, validitySeconds);

        String content;
        try {
            content = JsonUtils.writeValueAsString(
                createJWTRefreshToken(
                    token,
                    tokenId,
                    user,
                    authentication.getOAuth2Request().getScope(),
                    authentication.getOAuth2Request().getClientId(),
                    grantType,
                    additionalAuthorizationAttributes,authentication.getOAuth2Request().getResourceIds(),
                    revocableHashSignature,
                    revocable,
                    externalAttributes
                )
            );
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        String jwtToken = JwtHelper.encode(content, getActiveKeyInfo().getSigner()).getEncoded();

        ExpiringOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken(jwtToken, token.getExpiration());

        return refreshToken;
    }

    private KeyInfo getActiveKeyInfo() {
        return ofNullable(KeyInfo.getActiveKey())
            .orElseThrow(() -> new InternalAuthenticationServiceException("Unable to sign token, misconfigured JWT signing keys"));
    }

    private Map<String, ?> createJWTRefreshToken(
        OAuth2RefreshToken token,
        String tokenId,
        UaaUser user,
        Set<String> scopes,
        String clientId,
        String grantType,
        Map<String, String> additionalAuthorizationAttributes,
        Set<String> resourceIds,
        String revocableSignature,
        boolean revocable,
        Map<String, Object> externalAttributes) {

        Map<String, Object> response = new LinkedHashMap<>();

        response.put(JTI, tokenId);
        response.put(SUB, user.getId());
        response.put(GRANTED_SCOPES, scopes);
        if (null != additionalAuthorizationAttributes) {
            response.put(ADDITIONAL_AZ_ATTR, additionalAuthorizationAttributes);
        }
        if (null != externalAttributes) {
            response.putAll(externalAttributes);
        }

        response.put(IAT, System.currentTimeMillis() / 1000);
        if (((ExpiringOAuth2RefreshToken) token).getExpiration() != null) {
            response.put(EXP, ((ExpiringOAuth2RefreshToken) token).getExpiration().getTime() / 1000);
        }

        response.put(CID, clientId);
        response.put(CLIENT_ID, clientId);
        if (getTokenEndpoint() != null) {
            response.put(ISS, getTokenEndpoint());
            response.put(ZONE_ID, IdentityZoneHolder.get().getId());
        }

        if (revocable) {
            response.put(ClaimConstants.REVOCABLE, true);
        }

        if (null != grantType) {
            response.put(GRANT_TYPE, grantType);
        }
        if (user!=null) {
            response.put(USER_NAME, user.getUsername());
            response.put(ORIGIN, user.getOrigin());
            response.put(USER_ID, user.getId());
        }

        if (hasText(revocableSignature)) {
            response.put(REVOCATION_SIGNATURE, revocableSignature);
        }

        response.put(AUD, resourceIds);

        return response;
    }

    private String getTokenEndpoint() {
        return new TokenEndpointBuilder(issuer).getTokenEndpoint();
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
}
