package org.cloudfoundry.identity.uaa.oauth;

import org.bouncycastle.asn1.ASN1Sequence;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtAlgorithms;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.web.util.UriComponentsBuilder;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.MAC;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.RSA;
import static org.springframework.security.jwt.codec.Codecs.b64Decode;
import static org.springframework.security.jwt.codec.Codecs.utf8Encode;

public abstract class KeyInfo {
    public abstract void verify();

    public abstract SignatureVerifier getVerifier();

    public abstract Signer getSigner();

    public abstract String keyId();

    public abstract String keyURL();

    public abstract String type();

    public abstract String verifierKey();

    public abstract Map<String, Object> getJwkMap();

    public abstract String algorithm();

    protected String validateAndConstructTokenKeyUrl(String keyUrl) {
        if (!UaaUrlUtils.isUrl(keyUrl)) {
            throw new IllegalArgumentException("Invalid Key URL");
        }

        return UriComponentsBuilder.fromHttpUrl(keyUrl).scheme("https").path("/token_keys").build().toUriString();
    }
}

class HmacKeyInfo extends KeyInfo {
    private Signer signer;
    private SignatureVerifier verifier;
    private final String keyId;
    private final String keyUrl;
    private final String verifierKey;

    public HmacKeyInfo(String keyId, String signingKey, String keyUrl) {
        this.keyUrl = validateAndConstructTokenKeyUrl(keyUrl);

        this.signer = new MacSigner(signingKey);
        this.verifier = new MacSigner(signingKey);

        this.keyId = keyId;
        this.verifierKey = signingKey;
    }

    @Override
    public void verify() {

    }

    @Override
    public SignatureVerifier getVerifier() {
        return this.verifier;
    }

    @Override
    public Signer getSigner() {
        return this.signer;
    }

    @Override
    public String keyId() {
        return this.keyId;
    }

    @Override
    public String keyURL() {
        return this.keyUrl;
    }

    @Override
    public String type() {
        return MAC.name();
    }

    @Override
    public String verifierKey() {
        return this.verifierKey;
    }

    @Override
    public Map<String, Object> getJwkMap() {
        Map<String, Object> result = new HashMap<>();
        result.put("alg", this.algorithm());
        result.put("value", this.verifierKey);
        //new values per OpenID and JWK spec
        result.put("use", JsonWebKey.KeyUse.sig.name());
        result.put("kid", this.keyId);
        result.put("kty", MAC.name());
        return result;
    }

    @Override
    public String algorithm() {
        return JwtAlgorithms.sigAlg(verifier.algorithm());
    }
}

class RsaKeyInfo extends KeyInfo {
    private static Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", Pattern.DOTALL);
    private static final java.util.Base64.Encoder base64encoder = java.util.Base64.getMimeEncoder(64, "\n".getBytes());
    private final String keyId;
    private final String keyUrl;

    private Signer signer;
    private SignatureVerifier verifier;
    private String verifierKey;

    public RsaKeyInfo(String keyId, String signingKey, String keyUrl) {
        this.keyUrl = validateAndConstructTokenKeyUrl(keyUrl);

        KeyPair keyPair = parseKeyPair(signingKey);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        String pemEncodePublicKey = pemEncodePublicKey(rsaPublicKey);

        this.signer = new RsaSigner(signingKey);
        this.verifier = new RsaVerifier(pemEncodePublicKey);
        this.keyId = keyId;
        this.verifierKey = pemEncodePublicKey;
    }

    private KeyPair parseKeyPair(String pemData) {
        Matcher m = PEM_DATA.matcher(pemData.trim());

        if (!m.matches()) {
            throw new IllegalArgumentException("String is not PEM encoded data");
        }

        String type = m.group(1);
        final byte[] content = b64Decode(utf8Encode(m.group(2)));

        PublicKey publicKey;
        PrivateKey privateKey = null;

        try {
            KeyFactory fact = KeyFactory.getInstance("RSA");
            if (type.equals("RSA PRIVATE KEY")) {
                ASN1Sequence seq = ASN1Sequence.getInstance(content);
                if (seq.size() != 9) {
                    throw new IllegalArgumentException("Invalid RSA Private Key ASN1 sequence.");
                }
                org.bouncycastle.asn1.pkcs.RSAPrivateKey key = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(seq);
                RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
                RSAPrivateCrtKeySpec privSpec = new RSAPrivateCrtKeySpec(
                  key.getModulus(),
                  key.getPublicExponent(),
                  key.getPrivateExponent(),
                  key.getPrime1(),
                  key.getPrime2(),
                  key.getExponent1(),
                  key.getExponent2(),
                  key.getCoefficient()
                );
                publicKey = fact.generatePublic(pubSpec);
                privateKey = fact.generatePrivate(privSpec);
            } else if (type.equals("PUBLIC KEY")) {
                KeySpec keySpec = new X509EncodedKeySpec(content);
                publicKey = fact.generatePublic(keySpec);
            } else if (type.equals("RSA PUBLIC KEY")) {
                ASN1Sequence seq = ASN1Sequence.getInstance(content);
                org.bouncycastle.asn1.pkcs.RSAPublicKey key = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(seq);
                RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
                publicKey = fact.generatePublic(pubSpec);
            } else {
                throw new IllegalArgumentException(type + " is not a supported format");
            }

            return new KeyPair(publicKey, privateKey);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private String pemEncodePublicKey(PublicKey publicKey) {
        String begin = "-----BEGIN PUBLIC KEY-----\n";
        String end = "\n-----END PUBLIC KEY-----";
        byte[] data = publicKey.getEncoded();
        String base64encoded = new String(base64encoder.encode(data));

        return begin + base64encoded + end;
    }

    @Override
    public void verify() {
    }

    @Override
    public SignatureVerifier getVerifier() {
        return this.verifier;
    }

    @Override
    public Signer getSigner() {
        return this.signer;
    }

    @Override
    public String keyId() {
        return this.keyId;
    }

    @Override
    public String keyURL() {
        return this.keyUrl;
    }

    @Override
    public String type() {
        return RSA.name();
    }

    @Override
    public String verifierKey() {
        return this.verifierKey;
    }

    @Override
    public Map<String, Object> getJwkMap() {
        Map<String, Object> result = new HashMap<>();
        result.put("alg", this.algorithm());
        result.put("value", this.verifierKey);
        //new values per OpenID and JWK spec
        result.put("use", JsonWebKey.KeyUse.sig.name());
        result.put("kid", this.keyId);
        result.put("kty", RSA.name());

        RSAPublicKey rsaKey = (RSAPublicKey) parseKeyPair(verifierKey).getPublic();
        if (rsaKey != null) {
            java.util.Base64.Encoder encoder = java.util.Base64.getUrlEncoder().withoutPadding();
            String n = encoder.encodeToString(rsaKey.getModulus().toByteArray());
            String e = encoder.encodeToString(rsaKey.getPublicExponent().toByteArray());
            result.put("n", n);
            result.put("e", e);
        }

        return result;
    }

    @Override
    public String algorithm() {
        return JwtAlgorithms.sigAlg(verifier.algorithm());
    }
}
