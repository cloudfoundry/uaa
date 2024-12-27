package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.HMAC;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKParameterNames;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.cloudfoundry.identity.uaa.oauth.InvalidSignatureException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * This class is a fork to nimbus-jose because
 * UAA has legacy key and key sizes. Removing the support
 * of this, would be a regression.
 */
public class UaaMacSigner implements JWSSigner {

    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;

    static {
        Set<JWSAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWSAlgorithm.HS256);
        algs.add(JWSAlgorithm.HS384);
        algs.add(JWSAlgorithm.HS512);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }

    private final SecretKey secretKey;

    public UaaMacSigner(String secretKey) {
        this(new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "HS256"));
    }

    public UaaMacSigner(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public byte[] getSecret() {
        if (this.secretKey != null) {
            return secretKey.getEncoded();
        } else {
            throw new IllegalStateException("Unexpected state");
        }
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        String jcaAlg = JwtAlgorithms.sigAlgJava(header.getAlgorithm().getName());
        byte[] hmac = HMAC.compute(jcaAlg, secretKey, signingInput, getJCAContext().getProvider());
        return Base64URL.encode(hmac);
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return SUPPORTED_ALGORITHMS;
    }

    @Override
    public JCAContext getJCAContext() {
        return new JCAContext();
    }

    // legacy method to replace HMAC verify. JOSE library does not allow to verify HMAC with a small key
    public static JWTClaimsSet verify(String jwToken, JWKSet jwkSet) {
        SignedJWT token;
        try {
            token = (SignedJWT) JWTParser.parse(jwToken);
            JWSHeader header = token.getHeader();
            String kid = header.getKeyID();
            JWK jwKey = jwkSet.getKeys().stream().filter(e -> kid.equals(e.getKeyID())).findFirst().orElseThrow();
            UaaMacSigner internal = new UaaMacSigner((String) jwKey.toJSONObject().get(JWKParameterNames.OCT_KEY_VALUE));
            // symmetric signature check: create internal signature and compare if matches the signature from token
            if (token.getSignature().equals(internal.sign(header, token.getSigningInput())) && SUPPORTED_ALGORITHMS.contains(header.getAlgorithm())) {
                return token.getJWTClaimsSet();
            }
            throw new InvalidSignatureException("HMAC not mached");
        } catch (ParseException | JOSEException e) {
            throw new InvalidSignatureException("Invalid signed token", e);
        }
    }
}
