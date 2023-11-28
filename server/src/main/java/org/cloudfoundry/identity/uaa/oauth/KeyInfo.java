package org.cloudfoundry.identity.uaa.oauth;

import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKParameterNames;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwt.CommonSignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtAlgorithms;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.jwt.UaaMacSigner;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.EC;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.MAC;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.RSA;

public class KeyInfo {
    private final boolean isAsymmetric;
    private JWSSigner signer;
    private CommonSignatureVerifier verifier;
    private final String keyId;
    private final String keyUrl;
    private final String verifierKey;
    private final Optional<X509Certificate> verifierCertificate;
    private final JsonWebKey.KeyType type;
    private final JWK jwk;
    private final String javaAlgorithm;
    private final String algorithm;

    public KeyInfo(String keyId, String signingKey, String keyUrl) {
        this(keyId, signingKey, keyUrl, null, null);
    }
    public KeyInfo(String keyId, String signingKey, String keyUrl, String sigAlg, String signingCert) {
        this.keyId = keyId;
        this.keyUrl = validateAndConstructTokenKeyUrl(keyUrl);
        this.isAsymmetric = isAsymmetric(signingKey);
        if (this.isAsymmetric) {
            String jwtAlg;
            KeyPair keyPair;
            try {
                jwk = JWK.parseFromPEMEncodedObjects(signingKey);
                jwtAlg = jwk.getKeyType().getValue();
                if (jwtAlg.startsWith("RSA")) {
                    javaAlgorithm = Optional.ofNullable(sigAlg).map(JwtAlgorithms::sigAlgJava).orElse(JwtAlgorithms.DEFAULT_RSA);
                    algorithm = Optional.ofNullable(sigAlg).orElse(JWSAlgorithm.RS256.getName());
                    keyPair = jwk.toRSAKey().toKeyPair();
                    PublicKey rsaPublicKey = keyPair.getPublic();
                    this.signer = new RSASSASigner(keyPair.getPrivate(), true);// null;//new JWSSigner(null, null);//new RsaSigner((RSAPrivateKey) keyPair.getPrivate(), algorithm);
                    this.verifier = new CommonSignatureVerifier(keyId, algorithm, jwk);//new RsaVerifier((RSAPublicKey) rsaPublicKey, algorithm);
                    this.type = RSA;
                } else if (jwtAlg.startsWith("EC")) {
                    javaAlgorithm = Optional.ofNullable(sigAlg).map(JwtAlgorithms::sigAlgJava).orElse(JwtAlgorithms.DEFAULT_EC);
                    algorithm = Optional.ofNullable(sigAlg).orElse(JWSAlgorithm.ES256.getName());
                    keyPair = jwk.toECKey().toKeyPair();
                    this.signer = new ECDSASigner((ECPrivateKey) keyPair.getPrivate());
                    this.verifier = new CommonSignatureVerifier(keyId, algorithm, jwk);//new EllipticCurveVerifier((ECPublicKey) keyPair.getPublic(), algorithm);
                    this.type = EC;
                } else {
                    throw new IllegalArgumentException("Invalid JWK");
                }
            } catch (JOSEException e) {
                throw new IllegalArgumentException(e);
            }
            this.verifierCertificate = getValidX509Certificate(signingCert);
            this.verifierKey = JsonWebKey.pemEncodePublicKey(keyPair.getPublic()).orElse(null);
        } else {
            jwk = new OctetSequenceKey.Builder(signingKey.getBytes()).build();
            javaAlgorithm = Optional.ofNullable(sigAlg).map(JwtAlgorithms::sigAlgJava).orElse(JwtAlgorithms.DEFAULT_HMAC);
            algorithm = Optional.ofNullable(sigAlg).orElse(JWSAlgorithm.HS256.getName());
            SecretKey hmacKey = new SecretKeySpec(signingKey.getBytes(), algorithm);
            this.signer = new UaaMacSigner(hmacKey);//new MacSigner(algorithm, hmacKey);
            this.verifier = new CommonSignatureVerifier(keyId, algorithm, jwk);//new MacSigner(algorithm, hmacKey);
            this.verifierKey = signingKey;
            this.verifierCertificate = Optional.empty();
            this.type = MAC;
        }
    }

    public CommonSignatureVerifier getVerifier() {
        return this.verifier;
    }

    public JWSSigner getSigner() {
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

    public Optional<X509Certificate> verifierCertificate() {
        return this.verifierCertificate;
    }

    public Map<String, Object> getJwkMap() {
        Map<String, Object> result = new HashMap<>();
        result.put(HeaderParameterNames.ALGORITHM, this.algorithm());
        //new values per OpenID and JWK spec
        result.put(JWKParameterNames.PUBLIC_KEY_USE, JsonWebKey.KeyUse.sig.name());
        result.put(HeaderParameterNames.KEY_ID, this.keyId);
        result.put(JWKParameterNames.KEY_TYPE, type.name());
        if (this.isAsymmetric) {
            // X509 releated values from JWK spec
            if (this.verifierCertificate.isPresent()) {
                X509Certificate x509Certificate = verifierCertificate.get();
                if (x509Certificate != null) {
                    byte[] encoded = JwtHelper.getX509CertEncoded(x509Certificate);
                    result.put(HeaderParameterNames.X_509_CERT_CHAIN, Collections.singletonList(Base64.encode(encoded).toString()));
                    result.put(HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT, JwtHelper.getX509CertThumbprint(encoded, "SHA-1"));
                    result.put(HeaderParameterNames.X_509_CERT_SHA_256_THUMBPRINT, JwtHelper.getX509CertThumbprint(encoded, "SHA-256"));
                }
            }
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
            result.put(JsonWebKey.PUBLIC_KEY_VALUE, this.verifierKey);
            return result;
        }
    }

    public String algorithm()  {
        return algorithm;
    }

    private static String validateAndConstructTokenKeyUrl(String keyUrl) {
        if (!UaaUrlUtils.isUrl(keyUrl)) {
            throw new IllegalArgumentException("Invalid Key URL");
        }

        return UriComponentsBuilder.fromHttpUrl(keyUrl).scheme("https").path("/token_keys").build().toUriString();
    }

    private static boolean isAsymmetric(String key) {
        return key.startsWith("-----BEGIN");
    }

    private Optional<X509Certificate> getValidX509Certificate(String pemEncoded) {
        try {
            if (pemEncoded != null && isAsymmetric(pemEncoded)) {
                X509Certificate x509Certificate = X509CertUtils.parse(pemEncoded);
                x509Certificate.checkValidity();
                return Optional.of(x509Certificate);
            }
        } catch (RuntimeException | CertificateExpiredException | CertificateNotYetValidException e) { } // ignore
        return Optional.empty();
    }
}
