package org.cloudfoundry.identity.uaa.spiffe;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;

/** Verifies the workload's proof-of-possession of the instance private key. */
@Component
@ConditionalOnProperty(prefix = "uaa.spiffe", name = "instance-identity-ca")
public class ProofOfPossessionVerifier {

    private final SpiffeProperties properties;

    public ProofOfPossessionVerifier(SpiffeProperties properties) {
        this.properties = properties;
    }

    public boolean isValid(X509Certificate certificate, String spiffeId, String audience,
                           long timestamp, String base64Signature) {
        if (!properties.popEnabled()) {
            return true;
        }
        if (Math.abs(Instant.now().getEpochSecond() - timestamp) > properties.popFreshnessSeconds()) {
            return false;
        }
        String message = spiffeId + "\n" + audience + "\n" + timestamp;
        try {
            Signature signature = Signature.getInstance(
                    algorithmFor(certificate.getPublicKey()), BouncyCastleFipsProvider.PROVIDER_NAME);
            signature.initVerify(certificate.getPublicKey());
            signature.update(message.getBytes(StandardCharsets.UTF_8));
            return signature.verify(Base64.getDecoder().decode(base64Signature));
        } catch (Exception e) {
            return false;
        }
    }

    private static String algorithmFor(PublicKey publicKey) {
        return switch (publicKey.getAlgorithm()) {
            case "EC" -> "SHA256withECDSA";
            case "RSA" -> "SHA256withRSA";
            default -> throw new IllegalArgumentException("Unsupported key type: " + publicKey.getAlgorithm());
        };
    }
}
