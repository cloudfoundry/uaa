package org.cloudfoundry.identity.uaa.provider.saml;

import java.security.cert.CertificateException;

public class CertificateRuntimeException extends RuntimeException {
    public CertificateRuntimeException(CertificateException e) {
        super(e);
    }
}
