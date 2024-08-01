package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.AllArgsConstructor;
import lombok.Getter;

import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_DIGEST_SHA1;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_DIGEST_SHA256;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_DIGEST_SHA512;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512;

@Getter
@AllArgsConstructor
public enum SignatureAlgorithm {
    SHA1(ALGO_ID_DIGEST_SHA1, ALGO_ID_SIGNATURE_RSA_SHA1),
    SHA256(ALGO_ID_DIGEST_SHA256, ALGO_ID_SIGNATURE_RSA_SHA256),
    SHA512(ALGO_ID_DIGEST_SHA512, ALGO_ID_SIGNATURE_RSA_SHA512),

    // Default to SHA256 when the algorithm is not recognized, but allow it to be checked as invalid
    INVALID(ALGO_ID_DIGEST_SHA256, ALGO_ID_SIGNATURE_RSA_SHA256);

    private final String digestAlgorithmURI;
    private final String signatureAlgorithmURI;
}
