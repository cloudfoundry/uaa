package org.cloudfoundry.identity.uaa.provider.token;

import com.fasterxml.jackson.core.type.TypeReference;
import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;
import com.ge.predix.pki.device.spi.PublicKeyNotFoundException;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.KeyProviderConfig;
import org.cloudfoundry.identity.uaa.provider.KeyProviderProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;

public class JwtBearerAssertionTokenAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(JwtBearerAssertionTokenAuthenticator.class);
    private ClientDetailsService clientDetailsService;
    private DevicePublicKeyProvider clientPublicKeyProvider;
    private final int maxAcceptableClockSkewSeconds = 60;
    private final ClientAssertionHeaderAuthenticator headerAuthenticator;

    private final String issuerURL;
    private KeyProviderProvisioning keyProviderProvisioning;
    private TokenGranter dcsEndpointTokenGranter;

    public JwtBearerAssertionTokenAuthenticator(final String issuerURL, final int clientHeaderTTL) {
        this.issuerURL = issuerURL;
        this.headerAuthenticator = new ClientAssertionHeaderAuthenticator(clientHeaderTTL);
    }

    public void setClientPublicKeyProvider(final DevicePublicKeyProvider clientPublicKeyProvider) {
        this.clientPublicKeyProvider = clientPublicKeyProvider;
    }

    public void setClientDetailsService(final ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    /**
     * Performs authentication of proxy assertion header prior to authenticating JWT assertion token
     *
     * @param proxyAssertionHeader
     *            Value of 'Predix-Client-Assertion' header. This is used to identify the deviceId,tenantId of the
     *            device authenticated over TLS by the proxy.
     *
     * @return An Authentication object if authentication is successful
     * @throws AuthenticationException
     *             if authentication failed
     */
    public Authentication authenticate(final String jwtAssertionToken, final String proxyAssertionHeader,
            final String proxyPublicKey) throws AuthenticationException {
        Map<String, Object> headerClaims = this.headerAuthenticator.authenticate(proxyAssertionHeader, proxyPublicKey);
        Jwt jwtAssertion = decodeJwt(jwtAssertionToken);
        assertJwtAssertionSubjectMatch(headerClaims, jwtAssertion);
        return authenticateJwtAssertionToken(jwtAssertion, getPublicKey(headerClaims));
    }

    // Fails unless sub claim in both parameters is the same
    private void assertJwtAssertionSubjectMatch(final Map<String, Object> headerClaims, final Jwt jwtAssertion) {
        Map<String, Object> jwtAssertionClaims = claimsMap(jwtAssertion.getClaims());

        // require subject claim
        if (!StringUtils.hasText((String) jwtAssertionClaims.get(ClaimConstants.SUB))) {
            throw new BadCredentialsException("Subject claim is required in jwt-bearer assertion.");
        }

        try {
            String headerSubject = (String) headerClaims.get(ClaimConstants.SUB);
            String jwtAssertionSubject = (String) jwtAssertionClaims.get(ClaimConstants.SUB);
            if (headerSubject.equals(jwtAssertionSubject)) {
                return;
            }
        } catch (RuntimeException e) {
            logger.debug(e.getMessage());
            throw new BadCredentialsException("Invalid JWT token.");
        }
        throw new BadCredentialsException("Invalid jwt-bearer assertion.");
    }

    /**
     * @return An Authentication object if authentication is successful
     * @throws AuthenticationException
     *             must throw this if authentication failed
     */
    public Authentication authenticateWithoutClientAssertionHeader(final String jwtAssertionToken)
            throws AuthenticationException {
        Jwt jwt = decodeJwt(jwtAssertionToken);
        return authenticateJwtAssertionToken(jwt, getPublicKey(claimsMap(jwt.getClaims())));
    }

    /**
     * @throws AuthenticationException
     *             must throw this if authentication fails
     */
    private Authentication authenticateJwtAssertionToken(final Jwt jwt, final String devicePublicKey)
            throws AuthenticationException {
        try {
            Map<String, Object> claims = claimsMap(jwt.getClaims());
            jwt.verifySignature(getVerifier(devicePublicKey));

            validateClaims(claims);

            String issuer = (String) claims.get(ClaimConstants.ISS);
            assertSubjectIsAuthorized(issuer, (String) claims.get(ClaimConstants.SUB));

            assertAudience(claims, this.issuerURL);
            assertTokenIsCurrent(claims);

            return new UsernamePasswordAuthenticationToken(issuer, null,
                    // Authorities are populated during actual token grant in UaaTokenServices#createAccessToken
                    Collections.emptyList());

        } catch (RuntimeException e) {
            logger.debug("Validation failed for jwt-bearer assertion token. token:{" + jwt + "} error: " + e);
        }

        // Do not include error detail in this exception.
        throw new BadCredentialsException("Authentication of client failed.");
    }

    private void validateClaims(final Map<String, Object> claims) {
        // require subject claim
        if (!StringUtils.hasText((String) claims.get(ClaimConstants.SUB))) {
            throw new InvalidTokenException("sub claim is required in jwt-bearer assertion.");
        }

        // require tenant_id claim
        if (!StringUtils.hasText((String) claims.get(ClaimConstants.TENANT_ID))) {
            throw new InvalidTokenException("tenant_id claim is required in jwt-bearer assertion.");
        }

        // require issuer claim
        if (!StringUtils.hasText((String) claims.get(ClaimConstants.ISS))) {
            throw new InvalidTokenException("iss claim is required in jwt-bearer assertion.");
        }

        // require audience claim
        Object audience = claims.get(ClaimConstants.AUD);
        if (audience instanceof ArrayList) {
            ArrayList<?> audienceList = (ArrayList<?>) audience;
            if (audienceList.isEmpty()) {
                throw new InvalidTokenException("aud claim is required in jwt-bearer assertion.");
            }
        }
        else if(audience instanceof String) {
            if (!StringUtils.hasText((String) claims.get(ClaimConstants.AUD))) {
                throw new InvalidTokenException("aud claim is required in jwt-bearer assertion.");
            }
        }
        else {
            throw new InvalidTokenException("aud claim is in the wrong format.");
        }

        // require iat positive numeric claim
        Integer iat = null;
        try {
            iat = (Integer) claims.get(ClaimConstants.IAT);
        } catch (RuntimeException e) {
            throw new InvalidTokenException("iat claim is in the wrong format.");
        }
        if (iat == null) {
            throw new InvalidTokenException("iat claim is required in jwt-bearer assertion.");
        }

        // require positive numeric expiration claim
        Integer exp = null;
        try {
            exp = (Integer) claims.get(ClaimConstants.EXPIRY_IN_SECONDS);
        } catch (RuntimeException e) {
            throw new InvalidTokenException("exp claim is in the wrong format.");
        }
        if (exp == null) {
            throw new InvalidTokenException("exp claim is required in jwt-bearer assertion.");
        }
    }

    private Map<String, Object> claimsMap(final String claimsJson) {
        Map<String, Object> claims = JsonUtils.readValue(claimsJson, new TypeReference<Map<String, Object>>() {
            // Nothing to add here.
        });
        return claims;
    }

    private Jwt decodeJwt(final String jwtString) {
        try {
            if (StringUtils.hasText(jwtString)) {
                return JwtHelper.decode(jwtString);
            }
        } catch (RuntimeException e) {
            throw new BadCredentialsException("Invalid JWT token.", e);
        }

        throw new BadCredentialsException("Invalid JWT token.");
    }

    private String getPublicKey(final Map<String, Object> claims) {
        String base64UrlEncodedPublicKey = null;
        try {
            // Predix CAAS url base64URL decodes the public key.
            String tenantId = (String) claims.get(ClaimConstants.TENANT_ID);
            String deviceId = (String) claims.get(ClaimConstants.SUB);

            KeyProviderConfig keyProviderConfig = keyProviderProvisioning.findActive();
            String predixZoneId = keyProviderConfig != null ? keyProviderConfig.getDcsTenantId() : "";
            if (StringUtils.hasText(predixZoneId)) {
                ClientDetails dcsClient = clientDetailsService.loadClientByClientId(keyProviderConfig.getClientId());
                if(dcsClient != null) {
                    //generate a token from this UAA
                    TokenRequest tokenRequest = new TokenRequest(null, dcsClient.getClientId(),
                            Collections.singleton("pki.cert.key"), GRANT_TYPE_CLIENT_CREDENTIALS);
                    OAuth2AccessToken dcsAccessToken = dcsEndpointTokenGranter.grant(GRANT_TYPE_CLIENT_CREDENTIALS, tokenRequest);
                    base64UrlEncodedPublicKey = this.clientPublicKeyProvider.getPublicKeyWithToken(tenantId, deviceId,
                            predixZoneId, dcsAccessToken.getValue());
                    logger.debug("Public Key for tenant: " + base64UrlEncodedPublicKey);
                    return new String(Base64.getUrlDecoder().decode(base64UrlEncodedPublicKey));
                }
            }
            //fallback to global settings for dcs call
            base64UrlEncodedPublicKey = this.clientPublicKeyProvider.getPublicKey(tenantId, deviceId, "");
            logger.debug("Public Key for tenant: " + base64UrlEncodedPublicKey);
            return new String(Base64.getUrlDecoder().decode(base64UrlEncodedPublicKey));
        } catch (PublicKeyNotFoundException e) {
            logger.debug("Unable to retrieve public key to validate jwt-bearer assertion. Error: " + e);
        } catch (RuntimeException e) {
            logger.debug("Unable to retrieve public key to validate jwt-bearer assertion. Error: " + e);
        }

        throw new BadCredentialsException("Unknown client.");
    }

    private void assertSubjectIsAuthorized(final String clientId, final String claimedSubject) {
        ClientDetails client = this.clientDetailsService.loadClientByClientId(clientId);
        if (client == null) {
            throw new InvalidTokenException("Unknown client: " + clientId);
        }

        if (!isSubjectAuthorized(client, claimedSubject)) {
            throw new InvalidTokenException(
                    String.format("Unauthorized subject:(%s) for uaa client:(%s)", claimedSubject, clientId));
        }
    }

    private boolean isSubjectAuthorized(final ClientDetails expectedClient, final String claimedSubject) {
        String authorizedSubject = (String) expectedClient.getAdditionalInformation()
                .get(ClientConstants.ALLOWED_DEVICE_ID);

        if (StringUtils.hasText((authorizedSubject))) {
            return authorizedSubject.equals(claimedSubject);
        }
        return false;
    }

    private void assertAudience(final Map<String, Object> claims, final String issuerURL) {
        Object audienceObject = claims.get(ClaimConstants.AUD);
        if(audienceObject instanceof ArrayList) {
            ArrayList<?> audienceList = (ArrayList<?>) audienceObject;
            if(!audienceList.contains(issuerURL)) {
                throw new InvalidTokenException("Audience does not match.");
            }
        }
        else if(audienceObject instanceof String) {
            String audience = (String) audienceObject;
            if (StringUtils.isEmpty(audience) || !audience.equals(issuerURL)) {
                throw new InvalidTokenException("Audience does not match.");
            }
        }
        else {
            throw new InvalidTokenException("aud claim is in the wrong format.");
        }
    }

    private static SignatureVerifier getVerifier(final String signingKey) {
        if (signingKey.startsWith("-----BEGIN PUBLIC KEY-----")) {
            return new RsaVerifier(signingKey);
        }
        throw new InvalidTokenException("No RSA public key available for token verification.");
    }

    private void assertTokenIsCurrent(final Map<String, Object> claims) {
        long expSeconds = (Integer) claims.get(ClaimConstants.EXPIRY_IN_SECONDS);
        long expWithSkewMillis = (expSeconds + this.maxAcceptableClockSkewSeconds) * 1000;
        long currentTime = System.currentTimeMillis();

        if (currentTime > expWithSkewMillis) {
            throw new InvalidTokenException("Token is expired");
        }
    }

    public void setKeyProviderProvisioning(KeyProviderProvisioning keyProviderProvisioning) {
        this.keyProviderProvisioning = keyProviderProvisioning;
    }

    public void setDcsEndpointTokenGranter(TokenGranter dcsEndpointTokenGranter) {
        this.dcsEndpointTokenGranter = dcsEndpointTokenGranter;
    }
}
