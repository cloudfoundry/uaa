package org.cloudfoundry.identity.uaa.spiffe;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class ProofOfPossessionVerifierTests {

    private final SpiffeTestCerts.CertKey leaf =
            SpiffeTestCerts.newInstanceCert(SpiffeTestCerts.newCa(), "o", "s", "a");
    private final SpiffeProperties props = new SpiffeProperties("td", "ca", null, 60, true);
    private final ProofOfPossessionVerifier verifier = new ProofOfPossessionVerifier(props);

    private static final String SPIFFE_ID = "spiffe://td/cf/org/o/space/s/app/a/process/web";
    private static final String AUDIENCE = "https://api.example.com";

    private String sign(String spiffeId, String audience, long timestamp) throws Exception {
        String message = spiffeId + "\n" + audience + "\n" + timestamp;
        Signature sig = Signature.getInstance("SHA256withRSA", BouncyCastleFipsProvider.PROVIDER_NAME);
        sig.initSign(leaf.keyPair().getPrivate());
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(sig.sign());
    }

    @Test
    void acceptsFreshValidSignature() throws Exception {
        long now = Instant.now().getEpochSecond();
        String popSignature = sign(SPIFFE_ID, AUDIENCE, now);

        assertThat(verifier.isValid(leaf.certificate(), SPIFFE_ID, AUDIENCE, now, popSignature)).isTrue();
    }

    @Test
    void rejectsTamperedMessage() throws Exception {
        long now = Instant.now().getEpochSecond();
        String popSignature = sign(SPIFFE_ID, AUDIENCE, now);

        // Verifier recomputes the message with a different audience -> signature will not match.
        assertThat(verifier.isValid(leaf.certificate(), SPIFFE_ID, "https://evil.example.com", now, popSignature))
                .isFalse();
    }

    @Test
    void rejectsStaleTimestamp() throws Exception {
        long stale = Instant.now().getEpochSecond() - 600;
        String popSignature = sign(SPIFFE_ID, AUDIENCE, stale);

        assertThat(verifier.isValid(leaf.certificate(), SPIFFE_ID, AUDIENCE, stale, popSignature)).isFalse();
    }

    @Test
    void shortCircuitsWhenPopDisabled() {
        SpiffeProperties disabled = new SpiffeProperties("td", "ca", null, 60, false);
        ProofOfPossessionVerifier off = new ProofOfPossessionVerifier(disabled);

        assertThat(off.isValid(leaf.certificate(), SPIFFE_ID, AUDIENCE, 0L, "not-a-signature")).isTrue();
    }
}
