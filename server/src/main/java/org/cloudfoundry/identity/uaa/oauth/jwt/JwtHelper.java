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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class JwtHelper {
    static byte[] PERIOD = (".").getBytes(StandardCharsets.UTF_8);
    private static final Base64.Decoder base64decoder = Base64.getUrlDecoder();

    /**
     * Creates a token from an encoded token string.
     *
     * @param token the (non-null) encoded token (three Base-64 encoded strings separated
     *              by "." characters)
     */
    public static Jwt decode(String token) {
        return new JwtImpl(token);
    }

    public static Jwt encodePlusX5t(CharSequence content, KeyInfo keyInfo, X509Certificate x509Certificate) {
        JwtHeader header;
        HeaderParameters headerParameters = new HeaderParameters(keyInfo.algorithm(), keyInfo.keyId(), null);
        headerParameters.setX5t(getX509CertThumbprint(getX509CertEncoded(x509Certificate), "SHA-1"));
        header = JwtHeaderHelper.create(headerParameters);
        return createJwt(content, keyInfo, header);
    }

    public static Jwt encode(CharSequence content, KeyInfo keyInfo) {
        JwtHeader header;
        header = JwtHeaderHelper.create(keyInfo.algorithm(), keyInfo.keyId(), keyInfo.keyURL());
        return createJwt(content, keyInfo, header);
    }

    private static JwtImpl createJwt(CharSequence content, KeyInfo keyInfo, JwtHeader header) {
        return new JwtImpl(header, content, keyInfo.getSigner());
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
    static JwtHeader create(String header) {
        Header jwtHeader;
        try {
            jwtHeader = Header.parse(new Base64URL(header));
        } catch (ParseException e) {
          throw new IllegalArgumentException(e);
        }
        return new JwtHeader(jwtHeader.toString(), JsonUtils.convertValue(jwtHeader.toJSONObject(), HeaderParameters.class));
    }

    static JwtHeader create(String algorithm, String kid, String jku) {
        HeaderParameters headerParameters = new HeaderParameters(algorithm, kid, jku);

        return create(headerParameters);
    }

    static JwtHeader create(HeaderParameters headerParameters) {
        return new JwtHeader(JsonUtils.writeValueAsString(headerParameters), headerParameters);
    }
}

/**
 * Header part of JWT
 */
class JwtHeader {
    private final String bytes;

    final HeaderParameters parameters;

    /**
     * @param bytes      the decoded header
     * @param parameters the parameter values contained in the header
     */
    JwtHeader(String bytes, HeaderParameters parameters) {
        this.bytes = bytes;
        this.parameters = parameters;
    }

    public byte[] bytes() {
        return bytes.getBytes();
    }

    @Override
    public String toString() {
        return new String(bytes);
    }
}

class JwtImpl implements Jwt {
    private final String orgJwt;
    private final JWT interalJwt;
    private final JwtHeader header;

    private final CharSequence content;

    private final JWSSigner crypto;

    private String claims;
    private final JWTClaimsSet claimsSet;

    /**
     * @param header  the header, containing the JWS/JWE algorithm information.
     * @param content the base64-decoded "claims" segment (may be encrypted, depending on
     *                header information).
     * @param crypto  the base64-decoded "crypto" segment.
     */
    JwtImpl(JwtHeader header, CharSequence content, JWSSigner crypto) {
        this.header = header;
        this.content = content;
        this.crypto = crypto;
        try {
            this.claimsSet = JWTClaimsSet.parse(String.valueOf(content));
            JWSHeader joseHeader = JWSHeader.parse((Map<String, Object>) JsonUtils.convertValue(header.parameters, HashMap.class));
            if (crypto != null) {
                SignedJWT signedJWT = new SignedJWT(joseHeader, claimsSet);
                signedJWT.sign(crypto);
                interalJwt = signedJWT;
                orgJwt = null;
            } else {
                interalJwt = null;
                orgJwt = null;
            }
        } catch (ParseException | JOSEException e) {
            throw new InvalidTokenException("Invalid token", e);
        }
        //claims = utf8Decode(content);
    }

    JwtImpl(JwtHeader header, JWTClaimsSet claimsSet) {
        this.header = header;
        this.content = null;
        this.crypto = null;
        this.claimsSet = claimsSet;
        this.interalJwt = null;
        this.orgJwt = null;
    }

    JwtImpl(String token) {
        if (!StringUtils.hasLength(token)) {
            throw new InsufficientAuthenticationException("Unable to decode expected id_token");
        }
        try {
            this.interalJwt = JWTParser.parse(token);
            this.claimsSet = interalJwt.getJWTClaimsSet();
            this.header = new JwtHeader(null, JsonUtils.convertValue(interalJwt.getHeader().toJSONObject(), HeaderParameters.class));
            this.orgJwt = token;
        } catch (ParseException e) {
            throw new InvalidTokenException("Invalid token", e);
        }
        this.content = null;
        this.crypto = null;
    }
    /**
     * Validates a signature contained in the 'crypto' segment.
     *
     * @param verifier the signature verifier
     */
    @Override
    public void verifySignature(Object verifier) {
        if (interalJwt != null && verifier instanceof CommonSignatureVerifier commonSignatureVerifier) {
            validateClientJWToken(interalJwt, commonSignatureVerifier.getJwkSet());
            return;
        } else if (interalJwt != null && verifier instanceof ChainedSignatureVerifier chainedSignatureVerifier) {
            Exception last = new InvalidSignatureException("No matching keys found.");
            for (CommonSignatureVerifier delegate : chainedSignatureVerifier.getDelegates()) {
                try {
                    validateClientJWToken(interalJwt, delegate.getJwkSet(((JWSHeader) interalJwt.getHeader()).getKeyID()));
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

    private byte[] signingInput() {
        return null;
    }

    private byte[] safeB64UrlEncode(byte[] bytes) {
        return null;
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
        return orgJwt != null ? orgJwt : crypto != null && interalJwt != null ? interalJwt.serialize() : "";
    }

    @Override
    public String toString() {
        return header + " " + claims;
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
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier());

        try {
            return jwtProcessor.process(jwtAssertion, null);
        } catch (BadJWSException | BadJWTException jwtException) { // signature failed
            throw new InvalidSignatureException("Unauthorized token", jwtException);
        } catch (BadJOSEException | JOSEException e) { // key resolution, structure of JWT failed
            if (e instanceof KeyLengthException keyLengthException) {
                return UaaMacSigner.verify(jwtAssertion.getParsedString(), jwkSet);
            }
            throw new InvalidSignatureException("Untrusted token", e);
        }
    }
}
