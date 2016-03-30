package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.jwt.IdentifiedSigner;
import org.cloudfoundry.identity.uaa.oauth.jwt.Signer;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class KeyInfo {
    private final Base64.Encoder base64encoder = Base64.getMimeEncoder(64, "\n".getBytes());
    private String keyId;
    private String verifierKey = new RandomValueStringGenerator().generate();
    private String signingKey = verifierKey;
    private Signer signer = new IdentifiedSigner(null, new MacSigner(verifierKey));
    private SignatureVerifier verifier = new MacSigner(signingKey);
    private String type = "MAC";
    private RSAPublicKey rsaPublicKey;

    public Signer getSigner() {
        return signer;
    }

    /**
     * @return the verifierKey
     */
    public String getVerifierKey() {
        return verifierKey;
    }

    public String getSigningKey() {
        return signingKey;
    }

    public String getType() {
        return type;
    }

    public RSAPublicKey getRsaPublicKey() {
        return rsaPublicKey;
    }

    /**
     * @return true if the KeyInfo represents an asymmetric (RSA) key pair
     */
    public boolean isAssymetricKey() {
        return isAssymetricKey(verifierKey);
    }

    public SignatureVerifier getVerifier() {
        return verifier;
    }

    /**
     * @return true if the string represents an asymmetric (RSA) key
     */
    public static boolean isAssymetricKey(String key) {
        return key.startsWith("-----BEGIN");
    }

    protected String pemEncodePublicKey(PublicKey publicKey) {
        String begin = "-----BEGIN PUBLIC KEY-----\n";
        String end = "\n-----END PUBLIC KEY-----";
        byte[] data = publicKey.getEncoded();
        String base64encoded = new String(base64encoder.encode(data));

        return begin + base64encoded + end;
    }

    /**
     * Sets the JWT signing key and corresponding key for verifying siugnatures produced by this class.
     * <p>
     * The signing key can be either a simple MAC key or an RSA
     * key. RSA keys should be in OpenSSH format,
     * as produced by <tt>ssh-keygen</tt>.
     *
     * @param signingKey the key to be used for signing JWTs.
     */
    public void setSigningKey(String signingKey) {
        if (StringUtils.isEmpty(signingKey)) {
            throw new IllegalArgumentException("Signing key cannot be empty");
        }

        Assert.hasText(signingKey);
        signingKey = signingKey.trim();

        this.signingKey = signingKey;
        this.signer = new CommonSigner(keyId, signingKey);

        if (isAssymetricKey(signingKey)) {
            KeyPair keyPair = SignerProvider.parseKeyPair(signingKey);
            rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            verifierKey = pemEncodePublicKey(rsaPublicKey);
            type = "RSA";
        } else {
            // Assume it's an HMAC key
            this.verifierKey = signingKey;
            type = "MAC";
        }

        verifier = new CommonSignatureVerifier(verifierKey);
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        if(!StringUtils.hasText(keyId)){
            throw new IllegalArgumentException("KeyId should not be null or empty");
        }
        this.keyId = keyId;
        this.signer = new CommonSigner(keyId, signingKey);
    }
}
