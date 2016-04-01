package org.cloudfoundry.identity.uaa.provider.token;

import java.util.Base64;
import java.util.Collections;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;
import com.ge.predix.pki.device.spi.PublicKeyNotFoundException;

public class JwtBearerAssertionTokenAuthenticator {

    private final Log logger = LogFactory.getLog(getClass());
    private ClientDetailsService clientDetailsService;
    private DevicePublicKeyProvider clientPublicKeyProvider;
    private final int maxAcceptableClockSkewSeconds = 60;
    private final ClientAssertionHeaderAuthenticator headerAuthenticator = new ClientAssertionHeaderAuthenticator();

    private final String issuerURL;

    public JwtBearerAssertionTokenAuthenticator(final String issuerURL) {
        this.issuerURL = issuerURL;
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
     * @param proxyAssertionHeader Value of 'Predix-Client-Assertion' header. This is used to identify the
     *        deviceId,tenantId of the device authenticated over TLS by the proxy.
     *        
     * @return An Authentication object if authentication is successful
     * @throws AuthenticationException
     *             if authentication failed
     */
    public Authentication authenticate(final String jwtAssertionToken, final String proxyAssertionHeader,
            final String proxyPublicKey) throws AuthenticationException {
        String headerClaims = this.headerAuthenticator.authenticate(proxyAssertionHeader, proxyPublicKey);
        return assertToken(decodeJwt(jwtAssertionToken), getPublicKey(headerClaims));
    }

    /**
     * @return An Authentication object if authentication is successful
     * @throws AuthenticationException must throw this if authentication failed
     */
    public Authentication authenticate(final String jwtAssertionToken) throws AuthenticationException {
        Jwt jwt = decodeJwt(jwtAssertionToken);
        return assertToken(jwt, getPublicKey(jwt.getClaims()));
    }

    /**
     * @throws AuthenticationException must throw this if authentication fails
     */
    private Authentication assertToken(final Jwt jwt, String devicePublicKey) throws AuthenticationException {
        try {
            Map<String, Object> claims = claimsMap(jwt.getClaims());
            jwt.verifySignature(getVerifier(devicePublicKey));
            
            //Use 'sub' claim as the uaa client for issuing access token. This client must be provisioned in current
            //uaa zone to authorize access for the requesting subject.
            String deviceId = (String) claims.get(ClaimConstants.SUB);
            assertClientIdExists(deviceId);
            
            assertAudience(claims, this.issuerURL);
            assertTokenIsCurrent(claims);

            // Authorities are populated during actual token grant in UaaTokenServices#createAccessToken
            return new UsernamePasswordAuthenticationToken(deviceId, null, Collections.emptyList());
                    
        } catch (RuntimeException e) {
            this.logger.debug("Validation failed for jwt-bearer assertion token. token:{" + jwt + "} error: " + e);
        }

        // Do not include error detail in this exception.
        throw new BadCredentialsException("Authentication of client failed.");
    }

    private Map<String, Object> claimsMap(final String claimsJson) {
        Map<String, Object> claims = JsonUtils.readValue(claimsJson,
                new TypeReference<Map<String, Object>>() {
            // Nothing to add here.
        });
        return claims;
    }
    
    private Jwt decodeJwt(String jwtString) {
        try {
            if (StringUtils.hasText(jwtString)) {
                return JwtHelper.decode(jwtString);
            }
        } catch (RuntimeException e) {
            throw new BadCredentialsException("Invalid JWT token.", e);
        }

        throw new BadCredentialsException("Invalid JWT token.");
    }

    private String getPublicKey(final String claimsJson) {
        String base64UrlEncodedPublicKey = null;
        try {
            Map<String, Object> claims = claimsMap(claimsJson);
            // Predix CAAS url base64URL decodes the public key.
            String tenantId = (String) claims.get(ClaimConstants.TENANT_ID);
            String deviceId = (String) claims.get(ClaimConstants.SUB);
            base64UrlEncodedPublicKey = this.clientPublicKeyProvider.getPublicKey(tenantId, deviceId);
            this.logger.debug("Public Key for tenant: " + base64UrlEncodedPublicKey);
            return new String(Base64.getUrlDecoder().decode(base64UrlEncodedPublicKey));
        } catch (PublicKeyNotFoundException e) {
            this.logger.debug("Unable to retrieve public key to validate jwt-bearer assertion. Error: " + e);
        } catch (RuntimeException e) {
            this.logger.debug("Unable to retrieve public key to validate jwt-bearer assertion. Error: " + e);
        }

        throw new BadCredentialsException("Unknown client.");
    }

    private void assertClientIdExists(final String clientId) {
        ClientDetails expectedClient = this.clientDetailsService.loadClientByClientId(clientId);
        if (expectedClient == null) {
            throw new InvalidTokenException("Unknown client: " + clientId);
        }
    }

    private void assertAudience(final Map<String, Object> claims, final String issuerURL) {
        String audience = (String) claims.get(ClaimConstants.AUD);

        if (StringUtils.isEmpty(audience) || !audience.equals(issuerURL)) {
            throw new InvalidTokenException("Audience does not match.");
        }
    }

    private static SignatureVerifier getVerifier(final String signingKey) {
        if (signingKey.startsWith("-----BEGIN PUBLIC KEY-----")) {
            return new RsaVerifier(signingKey);
        }
        throw new InvalidTokenException("No RSA public key available for token verification.");
    }

    private void assertTokenIsCurrent(final Map<String, Object> claims) {
        long expSeconds = getExpClaim(claims);
        long expWithSkewMillis = (expSeconds + this.maxAcceptableClockSkewSeconds) * 1000;
        long currentTime = System.currentTimeMillis();

        if (currentTime > expWithSkewMillis) {
            throw new InvalidTokenException("Token is expired");
        }
    }

    private Long getExpClaim(final Map<String, Object> claims) {
        try {
            // Always converting to String to convert to long, to avoid class cast exceptions.
            return Long.valueOf(String.valueOf(claims.get(ClaimConstants.EXP)));
        } catch (RuntimeException e) {
            throw new InvalidTokenException("Expiration is in the wrong format.");
        }
    }
}
