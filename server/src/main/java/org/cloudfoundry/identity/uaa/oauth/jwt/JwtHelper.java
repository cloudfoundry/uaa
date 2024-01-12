package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.Header;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.cloudfoundry.identity.uaa.oauth.InvalidSignatureException;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.util.StringUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class JwtHelper {
    private JwtHelper() {

    }

    /**
     * Creates a token from an encoded token string.
     *
     * @param token the (non-null) encoded token (three Base-64 encoded strings separated
     *              by "." characters)
     */
    public static Jwt decode(String token) {
        return new JwtImpl(token);
    }

    public static Jwt encodePlusX5t(Map<String, Object> payLoad, KeyInfo keyInfo, X509Certificate x509Certificate) {
        JwtHeader header;
        HeaderParameters headerParameters = new HeaderParameters(keyInfo.algorithm(), keyInfo.keyId(), null);
        headerParameters.setX5t(getX509CertThumbprint(getX509CertEncoded(x509Certificate), "SHA-1"));
        header = JwtHeaderHelper.create(headerParameters);
        return createJwt(header, payLoad, keyInfo);
    }

    public static Jwt encode(Map<String, Object> payLoad, KeyInfo keyInfo) {
        JwtHeader header;
        header = JwtHeaderHelper.create(keyInfo.algorithm(), keyInfo.keyId(), keyInfo.keyURL());
        return new JwtImpl(header, payLoad, keyInfo.getSigner());
    }

    private static JwtImpl createJwt(JwtHeader header, Map<String, Object> payLoad, KeyInfo keyInfo) {
        return new JwtImpl(header, payLoad, keyInfo.getSigner());
    }

    public static byte[] getX509CertEncoded(X509Certificate x509Certificate) {
        try {
            return x509Certificate.getEncoded();
        } catch (RuntimeException | CertificateEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }
    public static String getX509CertThumbprint(byte[] derEncodedCert, String alg) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance(alg);
            return Base64URL.encode(sha256.digest(derEncodedCert)).toString();
        } catch (RuntimeException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

}

/**
 * Helper object for JwtHeader.
 * <p>
 * Handles the JSON parsing and serialization.
 */
class JwtHeaderHelper {
    private JwtHeaderHelper() {

    }

    static JwtHeader create(String header) {
        Header jwtHeader;
        try {
            jwtHeader = Header.parse(new Base64URL(header));
        } catch (ParseException e) {
          throw new IllegalArgumentException(e);
        }
        return new JwtHeader(JsonUtils.convertValue(jwtHeader.toJSONObject(), HeaderParameters.class));
    }

    static JwtHeader create(String algorithm, String kid, String jku) {
        HeaderParameters headerParameters = new HeaderParameters(algorithm, kid, jku);

        return create(headerParameters);
    }

    static JwtHeader create(HeaderParameters headerParameters) {
        return new JwtHeader(headerParameters);
    }
}

/**
 * Header part of JWT
 */
class JwtHeader {
    final HeaderParameters parameters;

    /**
     * @param parameters the parameter values contained in the header
     */
    JwtHeader(HeaderParameters parameters) {
        this.parameters = parameters;
    }

    @Override
    public String toString() {
        return parameters.toString();
    }
}

class JwtImpl implements Jwt {

    private static final String INVALID_TOKEN = "Invalid token";
    private final String parsedJwtObject;
    private final JWT signedJwtObject;
    private final JwtHeader header;
    private final CharSequence content;
    private final JWSSigner signature;
    private final JWTClaimsSet claimsSet;

    /**
     * @param header  the header, containing the JWS/JWE algorithm information.
     * @param payLoad the "claims" segment (may be encrypted, depending on
     *                header information).
     * @param signature  the base64-decoded "signature" segment.
     */
    JwtImpl(JwtHeader header, Map<String, Object> payLoad, JWSSigner signature) {
        this.header = header;
        this.signature = signature;
        this.parsedJwtObject = null;
        this.content = null;
        try {
            this.claimsSet = JWTClaimsSet.parse(payLoad);
            JWSHeader joseHeader = JWSHeader.parse(JsonUtils.convertValue(header.parameters, HashMap.class));
            if (signature != null) {
                SignedJWT signedJWT = new SignedJWT(joseHeader, claimsSet);
                signedJWT.sign(signature);
                signedJwtObject = signedJWT;
            } else {
                signedJwtObject = null;
            }
        } catch (ParseException | JOSEException e) {
            throw new InvalidTokenException(INVALID_TOKEN, e);
        }
    }

    JwtImpl(String token) {
        if (!StringUtils.hasLength(token)) {
            throw new InsufficientAuthenticationException("Unable to decode expected id_token");
        }
        try {
            this.signedJwtObject = JWTParser.parse(token);
            this.claimsSet = signedJwtObject.getJWTClaimsSet();
            this.header = new JwtHeader(JsonUtils.convertValue(signedJwtObject.getHeader().toJSONObject(), HeaderParameters.class));
            this.parsedJwtObject = token;
        } catch (ParseException e) {
            throw new InvalidTokenException(INVALID_TOKEN, e);
        }
        this.content = null;
        this.signature = null;
    }
    /**
     * Validates a signature contained in the 'signature' segment.
     *
     * @param verifier the signature verifier
     */
    @Override
    public void verifySignature(Verifier verifier) {
        if (signedJwtObject != null && verifier instanceof SignatureVerifier signatureVerifier) {
            validateClientJWToken(signedJwtObject, signatureVerifier.getJwkSet());
            return;
        } else if (signedJwtObject != null && verifier instanceof ChainedSignatureVerifier chainedSignatureVerifier) {
            Exception last = new InvalidSignatureException("No matching keys found.");
            for (SignatureVerifier delegate : chainedSignatureVerifier.getDelegates()) {
                try {
                    validateClientJWToken(signedJwtObject, delegate.getJwkSet(((JWSHeader) signedJwtObject.getHeader()).getKeyID()));
                    //success
                    return;
                } catch (Exception e) {
                    last = e;
                }
            }
            throw (last instanceof RuntimeException runtimeException) ? runtimeException : new RuntimeException(last);
        }
        throw new InvalidSignatureException("Signature validation failed");
    }

    public String getClaims() {
        return content != null ? String.valueOf(content) : claimsSet.toString();
    }

    @Override
    public JWTClaimsSet getClaimSet() {
        return claimsSet != null ? claimsSet : new JWTClaimsSet.Builder().build();
    }

    @Override
    public String getEncoded() {
        return isJwtParsedOrCreated() ? parsedJwtObject : getEncodedSignedJwt();
    }

    private boolean isJwtParsedOrCreated() {
        return parsedJwtObject != null;
    }

    private String getEncodedSignedJwt() {
        return signature != null && signedJwtObject != null ? signedJwtObject.serialize() : "";
    }

    @Override
    public String toString() {
        return getClaims();
    }


    public HeaderParameters getHeader() {
        return header == null ? null : header.parameters;
    }

    private JWTClaimsSet validateClientJWToken(JWT jwtAssertion, JWKSet jwkSet) {
        Algorithm algorithm = jwtAssertion.getHeader().getAlgorithm();
        JWKSource<SecurityContext> keySource = new ImmutableJWKSet<>(jwkSet);
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>((JWSAlgorithm) algorithm, keySource);
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(keySelector);
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(null, null));

        try {
            return jwtProcessor.process(jwtAssertion, null);
        } catch (BadJWSException | BadJWTException jwtException) { // signature failed
            throw new InvalidSignatureException("Unauthorized token", jwtException);
        } catch (KeyLengthException ke ) {
            return UaaMacSigner.verify(jwtAssertion.getParsedString(), jwkSet);
        } catch (BadJOSEException | JOSEException e) { // key resolution, structure of JWT failed
            throw new InvalidSignatureException("Untrusted token", e);
        }
    }
}
