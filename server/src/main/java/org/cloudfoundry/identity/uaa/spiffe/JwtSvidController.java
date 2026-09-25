package org.cloudfoundry.identity.uaa.spiffe;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.regex.Pattern;

/** Issues UAA-signed JWT-SVIDs to authenticated Diego workload attestors. */
@RestController
@ConditionalOnProperty(prefix = "uaa.spiffe", name = "instance-identity-ca")
public class JwtSvidController {

    private static final Pattern PROCESS_TYPE_PATTERN = Pattern.compile("[a-zA-Z0-9_-]{1,63}");
    private static final int MAX_AUDIENCE_LENGTH = 512;

    private final CertificateOuParser ouParser;
    private final InstanceIdentityVerifier identityVerifier;
    private final ProofOfPossessionVerifier popVerifier;
    private final JwtSvidSigner signer;
    private final SpiffeProperties properties;

    public JwtSvidController(CertificateOuParser ouParser,
                            InstanceIdentityVerifier identityVerifier,
                            ProofOfPossessionVerifier popVerifier,
                            JwtSvidSigner signer,
                            SpiffeProperties properties) {
        this.ouParser = ouParser;
        this.identityVerifier = identityVerifier;
        this.popVerifier = popVerifier;
        this.signer = signer;
        this.properties = properties;
    }

    @PostMapping(value = "/jwt-svid/sign", consumes = "application/json", produces = "application/json")
    public JwtSvidResponse sign(@RequestBody JwtSvidRequest request) {
        validateRequest(request);
        X509Certificate certificate = parseCertificate(request.instanceCertificate());
        identityVerifier.verify(certificate);

        CfInstanceIdentity identity = ouParser.parse(certificate);
        String spiffeId = SpiffeId.format(properties.trustDomain(), identity, request.processType());

        if (!popVerifier.isValid(certificate, spiffeId, request.audience(),
                request.timestamp(), request.popSignature())) {
            throw new UnauthorizedRequestException("Proof-of-possession verification failed");
        }

        JwtSvidSigner.JwtSvidResult result =
                signer.sign(spiffeId, identity, request.processType(), request.audience());
        return new JwtSvidResponse(result.svid(), result.spiffeId(), result.expiresAt());
    }

    private static X509Certificate parseCertificate(String pem) {
        try {
            return new KeyWithCert(pem).getCertificate();
        } catch (CertificateException e) {
            throw new BadSvidRequestException("Unable to read instance certificate");
        }
    }

    /**
     * Rejects structurally dangerous input before it is concatenated into the SPIFFE ID
     * path ({@code process_type}) or the proof-of-possession message ({@code audience}).
     * Constraining both fields to printable, newline-free values keeps the signed PoP
     * message ({@code spiffeId \n audience \n timestamp}) unambiguous.
     */
    private static void validateRequest(JwtSvidRequest request) {
        String processType = request.processType();
        if (processType == null || !PROCESS_TYPE_PATTERN.matcher(processType).matches()) {
            throw new BadSvidRequestException("process_type must match [A-Za-z0-9_-]{1,63}");
        }
        String audience = request.audience();
        if (audience == null || audience.isBlank()
                || audience.length() > MAX_AUDIENCE_LENGTH
                || containsControlCharacter(audience)) {
            throw new BadSvidRequestException(
                    "audience must be non-blank, at most " + MAX_AUDIENCE_LENGTH
                            + " characters, and free of control characters");
        }
    }

    private static boolean containsControlCharacter(String value) {
        return value.chars().anyMatch(Character::isISOControl);
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static class UnauthorizedRequestException extends RuntimeException {
        public UnauthorizedRequestException(String message) {
            super(message);
        }
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public static class BadSvidRequestException extends RuntimeException {
        public BadSvidRequestException(String message) {
            super(message);
        }
    }

    /** Maps verifier/parser failures to HTTP status codes. */
    @ControllerAdvice
    public static class ExceptionHandling {

        @ExceptionHandler(InstanceIdentityVerifier.InvalidInstanceCertificateException.class)
        public ResponseEntity<String> handleUntrustedCertificate(
                InstanceIdentityVerifier.InvalidInstanceCertificateException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }

        @ExceptionHandler(IllegalArgumentException.class)
        public ResponseEntity<String> handleBadInput(IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }
}
