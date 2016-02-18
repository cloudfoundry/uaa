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

        try {
            PEMReader reader = new PEMReader(new InputStreamReader(new ByteArrayInputStream(certificate.getBytes())));
            cert = (X509Certificate) reader.readObject();

            reader = new PEMReader(new InputStreamReader(new ByteArrayInputStream(key.getBytes())), passphrase::toCharArray);
            pkey = (KeyPair) reader.readObject();
        } catch (IOException ex) {
            throw new CertificateException("Failed to read private key or certificate.", ex);
        } catch(Exception ex) {
            throw ex;
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
