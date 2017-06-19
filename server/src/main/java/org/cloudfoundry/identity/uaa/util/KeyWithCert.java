package org.cloudfoundry.identity.uaa.util;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class KeyWithCert {
    private X509Certificate cert;
    private KeyPair pkey;

    public KeyWithCert(String certificate) throws CertificateException {
        loadCertificate(certificate);
    }

    public KeyWithCert(String key, String passphrase, String certificate) throws CertificateException {
        if(passphrase == null) {
            passphrase = "";
        }

        PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(key.getBytes())));
        try {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof PEMEncryptedKeyPair) {
               PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(passphrase.toCharArray());
               pkey = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
            }
            else  if (object instanceof PEMKeyPair) {
                pkey = converter.getKeyPair((PEMKeyPair) object);
            }
            else if (object instanceof PrivateKeyInfo) {
                PrivateKey privKey = converter.getPrivateKey((PrivateKeyInfo) object);
                pkey = new KeyPair(null, privKey);
            }
        }
        catch (IOException ex) {
            throw new CertificateException("Failed to read private key.", ex);
        }
        finally {
            try {
                pemParser.close();
            }
            catch (IOException e) {
                throw new CertificateException("Failed to close key reader", e);
            }
        }
        if(pkey == null) {
           throw new CertificateException("Failed to read private key. The security provider could not parse it.");
        }

        loadCertificate(certificate);
        if (!cert.getPublicKey().equals(pkey.getPublic())) {
            throw new CertificateException("Certificate does not match private key.");
        }
    }

    public void loadCertificate(String certificate) throws CertificateException {
        PEMParser pemParser;
        pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(certificate.getBytes())));
        try {
            Object object = pemParser.readObject();
            if (object instanceof X509CertificateHolder) {
                cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder)object);
            }
            else {
                throw new CertificateException("Unsupported certificate type, not an X509CertificateHolder.");
            }
        }
        catch (IOException ex) {
            throw new CertificateException("Failed to read certificate.", ex);
        }
        finally {
            try {
                pemParser.close();
            }
            catch (IOException e) {
                throw new CertificateException("Failed to close certificate reader.", e);
            }
        }
        if(cert == null) {
            throw new CertificateException("Failed to read certificate. The security provider could not parse it.");
        }
    }

    public X509Certificate getCert() {
        return cert;
    }

    public KeyPair getPkey() {
        return pkey;
    }
}
