package org.cloudfoundry.identity.uaa.provider.token;

import java.util.Collections;
import java.util.List;
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
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;
import com.ge.predix.pki.device.spi.PublicKeyNotFoundException;

import javassist.expr.Instanceof;

public class JwtBearerAssertionTokenAuthenticator {

    private final Log logger = LogFactory.getLog(getClass());
    private ClientDetailsService clientDetailsService;
    private DevicePublicKeyProvider clientPublicKeyProvider;
    private final int maxAcceptableClockSkewSeconds = 60;
    
    private final String issuerURL;
    
    public JwtBearerAssertionTokenAuthenticator(String issuerURL) {
        this.issuerURL = issuerURL;
    }

    public void setClientPublicKeyProvider(DevicePublicKeyProvider clientPublicKeyProvider) {
        this.clientPublicKeyProvider = clientPublicKeyProvider;
    }

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    /**
     * @return An Authentication object if authentication is successful
     * @throws AuthenticationException if authentication failed
     */
    public Authentication authenticate(String token) throws AuthenticationException {
        Jwt jwt = null;
        try {
            if (StringUtils.hasText(token)) {
                jwt = JwtHelper.decode(token);
                Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(),
                        new TypeReference<Map<String, Object>>() {
                            // Nothing to add here.
                        });

                assertValidToken(jwt, claims);
                
                return new UsernamePasswordAuthenticationToken(claims.get(ClaimConstants.ISS), null,
                        //Authorities are populated later?
                        Collections.emptyList());
            } 
        } catch (RuntimeException e) {
            logger.debug("Validation failed for jwt-bearer assertion token. token:{"+jwt+"} error: "+e);
        }

        //Do not include error detail in this exception.
        throw new BadCredentialsException("Authentication of client failed.");
    }
    

    private String getPublicKey(Map<String, Object> claims)  {
        String base64UrlEncodedPublicKey;
        try {
            base64UrlEncodedPublicKey = this.clientPublicKeyProvider.getPublicKey((String)claims.
                    get(ClaimConstants.TENANT_ID),(String)claims.get(ClaimConstants.SUB));
        } catch (PublicKeyNotFoundException e) {
            throw new InvalidTokenException("Unknown client.");
        }
        // base64url decode this public key
        return new String(Base64Utils.decodeFromString(base64UrlEncodedPublicKey));
    }
    
    private void assertValidToken(Jwt jwt, Map<String, Object> claims) {
        assertJwtIssuer(claims);
        assertAudience(claims, issuerURL);
        assertTokenIsCurrent(claims);
        jwt.verifySignature(getVerifier(getPublicKey(claims)));
    }

    private void assertJwtIssuer(Map<String, Object> claims) {
        String client = (String) claims.get(ClaimConstants.ISS);
        ClientDetails expectedClient = clientDetailsService.loadClientByClientId(client);
        if (expectedClient == null) {
            throw new InvalidTokenException("Unknown token issuer : " + client);
        }
    }

    private void assertAudience(Map<String, Object> claims, String issuerURL) {
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
        
        if ( currentTime > expWithSkewMillis) {
            throw new InvalidTokenException("Token is expired");
        }
    }

    private Long getExpClaim(final Map<String, Object> claims) {
        Object expiration = claims.get(ClaimConstants.EXP);
        if(expiration instanceof String) {
            return Long.valueOf((String) expiration);
        }
        else if(expiration instanceof Long) {
            return (Long) expiration;
        }
        else {
            throw new InvalidTokenException("Expiration is in the wrong format.");
        }
    }

}
