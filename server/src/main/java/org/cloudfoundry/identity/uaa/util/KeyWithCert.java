package org.cloudfoundry.identity.uaa.util;

import org.bouncycastle.openssl.PEMReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class KeyWithCert {
    private X509Certificate cert;
    private KeyPair pkey;

    public KeyWithCert(String key, String passphrase, String certificate) throws CertificateException {
        if(passphrase == null) { passphrase = ""; }


        PEMReader reader;
        try {
            reader = new PEMReader(new InputStreamReader(new ByteArrayInputStream(key.getBytes())), passphrase::toCharArray);
            pkey = (KeyPair) reader.readObject();
            if(pkey == null) {
                throw new CertificateException("Failed to read private key. The security provider could not parse it.");
            }
        } catch (IOException ex) {
            throw new CertificateException("Failed to read private key.", ex);
        }
        try {
            reader = new PEMReader(new InputStreamReader(new ByteArrayInputStream(certificate.getBytes())));
            cert = (X509Certificate) reader.readObject();
            if(cert == null) {
                throw new CertificateException("Failed to read certificate. The security provider could not parse it.");
            }
        } catch (IOException ex) {
            throw new CertificateException("Failed to read certificate.", ex);
        }

        if (!cert.getPublicKey().equals(pkey.getPublic())) {
            throw new CertificateException("Certificate does not match private key.");
        }
    }

    public X509Certificate getCert() {
        return cert;
    }

    public KeyPair getPkey() {
        return pkey;
    }

}
