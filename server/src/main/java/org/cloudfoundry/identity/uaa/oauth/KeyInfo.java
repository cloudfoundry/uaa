package org.cloudfoundry.identity.uaa.oauth;

import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKParameterNames;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtAlgorithms;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.security.jwt.crypto.sign.EllipticCurveVerifier;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.web.util.UriComponentsBuilder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.EC;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.MAC;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.RSA;

public class KeyInfo {
    private final boolean isAsymetric;
    private Signer signer;
    private SignatureVerifier verifier;
    private final String keyId;
    private final String keyUrl;
    private final String verifierKey;
    private final JsonWebKey.KeyType type;
    private final JWK jwk;

    public KeyInfo(String keyId, String signingKey, String keyUrl) {
        this(keyId, signingKey, keyUrl, null);
    }
    public KeyInfo(String keyId, String signingKey, String keyUrl, String sigAlg) {
        this.keyId = keyId;
        this.keyUrl = validateAndConstructTokenKeyUrl(keyUrl);
        this.isAsymetric = isAssymetricKey(signingKey);
        String algorithm;
        if (this.isAsymetric) {
            String jwtAlg;
            KeyPair keyPair;
            try {
                jwk = JWK.parseFromPEMEncodedObjects(signingKey);
                jwtAlg = jwk.getKeyType().getValue();
                if (jwtAlg.startsWith("RSA")) {
                    algorithm = getJavaAlgorithm(sigAlg, "SHA256withRSA");
                    keyPair = jwk.toRSAKey().toKeyPair();
                    PublicKey rsaPublicKey = keyPair.getPublic();
                    this.signer = new RsaSigner((RSAPrivateKey) keyPair.getPrivate(), algorithm);
                    this.verifier = new RsaVerifier((RSAPublicKey) rsaPublicKey, algorithm);
                    this.type = RSA;
                } else if (jwtAlg.startsWith("EC")) {
                    algorithm = getJavaAlgorithm(sigAlg, "SHA256withECDSA");
                    keyPair = jwk.toECKey().toKeyPair();
                    this.signer = null;
                    this.verifier = new EllipticCurveVerifier((ECPublicKey) keyPair.getPublic(), algorithm);
                    this.type = EC;
                } else {
                    throw new IllegalArgumentException("Invalid JWK");
                }
            } catch (JOSEException e) {
                throw new IllegalArgumentException("PEM is not a supported format", e);
            }
            this.verifierKey = JsonWebKey.pemEncodePublicKey(keyPair.getPublic());
        } else {
            jwk = new OctetSequenceKey.Builder(signingKey.getBytes()).build();
            algorithm = getJavaAlgorithm(sigAlg, "HMACSHA256");
            SecretKey hmacKey = new SecretKeySpec(signingKey.getBytes(), algorithm);
            this.signer = new MacSigner(algorithm, hmacKey);
            this.verifier = new MacSigner(algorithm, hmacKey);
            this.verifierKey = signingKey;
            this.type = MAC;
        }
    }
    public void verify() {
        // not in use
    }

    public SignatureVerifier getVerifier() {
        return this.verifier;
    }

    public Signer getSigner() {
        return this.signer;
    }

    public String keyId() {
        return this.keyId;
    }

    public String keyURL() {
        return this.keyUrl;
    }

    public String type() {
        return this.type.name();
    }

    public String verifierKey() {
        return this.verifierKey;
    }

    public Map<String, Object> getJwkMap() {
        if (this.isAsymetric) {
            Map<String, Object> result = new HashMap<>();
            result.put(HeaderParameterNames.ALGORITHM, this.algorithm());
            //new values per OpenID and JWK spec
            result.put(JWKParameterNames.PUBLIC_KEY_USE, JsonWebKey.KeyUse.sig.name());
            result.put(HeaderParameterNames.KEY_ID, this.keyId);
            result.put(JWKParameterNames.KEY_TYPE, type.name());

            if (type == RSA) {
                RSAPublicKey rsaKey;
                try {
                    result.put(JsonWebKey.PUBLIC_KEY_VALUE, this.verifierKey);
                    rsaKey = jwk.toRSAKey().toRSAPublicKey();
                } catch (JOSEException e) {
                    throw new IllegalArgumentException(e);
                }
                String n = Base64URL.encode(rsaKey.getModulus()).toString();
                String e = Base64URL.encode(rsaKey.getPublicExponent()).toString();
                result.put(JWKParameterNames.RSA_MODULUS, n);
                result.put(JWKParameterNames.RSA_EXPONENT, e);
            } else if (type == EC) {
                result.putAll(jwk.toJSONObject());
            }
            return result;
        } else {
            Map<String, Object> result = new HashMap<>();
            result.put(HeaderParameterNames.ALGORITHM, this.algorithm());
            result.put(JsonWebKey.PUBLIC_KEY_VALUE, this.verifierKey);
            //new values per OpenID and JWK spec
            result.put(JWKParameterNames.PUBLIC_KEY_USE, JsonWebKey.KeyUse.sig.name());
            result.put(HeaderParameterNames.KEY_ID, this.keyId);
            result.put(JWKParameterNames.KEY_TYPE, type.name());
            return result;
        }
    }

    public String algorithm()  {
        return JwtAlgorithms.sigAlg(verifier.algorithm());
    }

    private static String getJavaAlgorithm(String sigAlg, String defaultAlg) {
        if (sigAlg == null) {
            if (defaultAlg == null) {
                throw new IllegalArgumentException("Invalid algorithm");
            }
            return defaultAlg;
        } else {
            return JwtAlgorithms.sigAlgJava(sigAlg);
        }
    }

    private static String validateAndConstructTokenKeyUrl(String keyUrl) {
        if (!UaaUrlUtils.isUrl(keyUrl)) {
            throw new IllegalArgumentException("Invalid Key URL");
        }

        return UriComponentsBuilder.fromHttpUrl(keyUrl).scheme("https").path("/token_keys").build().toUriString();
    }

    /**
     * @return true if the string represents an asymmetric (RSA) key
     */
    private static boolean isAssymetricKey(String key) {
        return key.startsWith("-----BEGIN");
    }
}
