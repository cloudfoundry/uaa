package org.cloudfoundry.identity.uaa.provider.token;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.opensaml.xml.encryption.Public;
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

    public static final String TOKEN_VERIFYING_KEY =  "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwRDzaYGaSfazjhVtf/HVgjzT0hV4lBX9vY2H93U2vtV0cX2ZVTXSd74UAApQejLCmcaA5aJzgtngcbZqqHlpPVLbjnQsL9vTj05KQX0fuFIytAahZt6dxDSfYi2UIZTusKEREyqlljptMuRMYJOsTVIQLKRuXj6hYrRvCiSg4ODk1+G/HbuN1xCymTcjNkviu5PAs01aUra3If2bN7rVXFDKCgDkJBhdE7FKrI++ScN6CGmPRrK54sv3D3LAu7zSeonswl4S4b4Fm5Ml7+Ik+YZovRghwutsbVtve0U1c48O6w//48Vgb+J7GzX/84fnHk0Ie/IegGnIQ3z02o6kuwIDAQAB-----END PUBLIC KEY-----";

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
        return new String(Base64.getUrlDecoder().decode(base64UrlEncodedPublicKey));
        //return new String(Base64Utils.decodeFromString(base64UrlEncodedPublicKey));
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
        try {
            //Always converting to String to convert to long, to avoid class cast exceptions.
            return Long.valueOf(String.valueOf(claims.get(ClaimConstants.EXP)));
        }
        catch(RuntimeException e) {
            throw new InvalidTokenException("Expiration is in the wrong format.");
        }
    }

}
