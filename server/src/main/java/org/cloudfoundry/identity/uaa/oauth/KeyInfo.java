package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.jwt.IdentifiedSigner;
import org.cloudfoundry.identity.uaa.oauth.jwt.Signer;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.KeyPair;
import java.util.Base64;

public class KeyInfo {
    private static final Log logger = LogFactory.getLog(KeyInfo.class);
    private final Base64.Encoder base64encoder = Base64.getMimeEncoder(64, "\n".getBytes());
    private String keyId;
    private String verifierKey = new RandomValueStringGenerator().generate();
    private String signingKey = verifierKey;
    private org.springframework.security.jwt.crypto.sign.Signer signer = new MacSigner(verifierKey);
    private SignatureVerifier verifier = new MacSigner(signingKey);
    private String type = "MAC";

    public Signer getSigner() {
        return new IdentifiedSigner(keyId, signer);
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

    /**
     * @return true if the signer represents a public (asymmetric) key pair
     */
    public boolean isPublic() {
        return verifierKey.startsWith("-----BEGIN");
    }

    public SignatureVerifier getVerifier() {
        return verifier;
    }

    /**
     * @return true if the key has a public verifier
     */
    private static boolean isAssymetricKey(String key) {
        return key.startsWith("-----BEGIN");
    }

    protected String pemEncodePublicKey(KeyPair keyPair) {
        String begin = "-----BEGIN PUBLIC KEY-----\n";
        String end = "\n-----END PUBLIC KEY-----";
        byte[] data = keyPair.getPublic().getEncoded();
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


        if (isAssymetricKey(signingKey)) {
            KeyPair keyPair = SignerProvider.parseKeyPair(signingKey);
            signer = new RsaSigner(signingKey);

            verifierKey = pemEncodePublicKey(keyPair);

            logger.debug("Configured with RSA signing key");
            try {
                verifier = new RsaVerifier(verifierKey);
            } catch (Exception e) {
                throw new RuntimeException("Unable to create an RSA verifier from verifierKey", e);
            }

            byte[] test = "test".getBytes();
            try {
                verifier.verify(test, signer.sign(test));
                logger.debug("Signing and verification RSA keys match");
            } catch (InvalidSignatureException e) {
                throw new RuntimeException("Signing and verification RSA keys do not match", e);
            }
            type = "RSA";
        } else {
            // Assume it's an HMAC key
            this.verifierKey = signingKey;
            MacSigner macSigner = new MacSigner(signingKey);
            signer = macSigner;
            verifier = macSigner;

            Assert.state(this.verifierKey == null || this.signingKey == this.verifierKey,
                "For MAC signing you do not need to specify the verifier key separately, and if you do it must match the signing key");
            type = "MAC";
        }
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        if(!StringUtils.hasText(keyId)){
            throw new IllegalArgumentException("KeyId should not be null or empty");
        }
        this.keyId = keyId;
    }
}
