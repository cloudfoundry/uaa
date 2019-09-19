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
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class KeyWithCert {
    private X509Certificate certificate;
    private PrivateKey privateKey;

    public KeyWithCert(String encodedCertificate) throws CertificateException {
        certificate = loadCertificate(encodedCertificate);
    }

    public KeyWithCert(String encodedPrivateKey, String passphrase, String encodedCertificate) throws CertificateException {
        if (passphrase == null) {
            passphrase = "";
        }

        privateKey = loadPrivateKey(encodedPrivateKey, passphrase);

        certificate = loadCertificate(encodedCertificate);

        if (!keysMatch(certificate.getPublicKey(), privateKey)) {
            throw new CertificateException("Certificate does not match private key.");
        }
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    private boolean keysMatch(PublicKey publicKey, PrivateKey privateKey) {
        byte[] data = {42};

        String privateKeyAlgorithm = privateKey.getAlgorithm();
        String publicKeyAlgorithm = publicKey.getAlgorithm();

        if (privateKeyAlgorithm.equals("EC")) {
            privateKeyAlgorithm = "ECDSA";
        }

        if (publicKeyAlgorithm.equals("EC")) {
            publicKeyAlgorithm = "ECDSA";
        }

        try {
            Signature sig = Signature.getInstance(privateKeyAlgorithm);
            sig.initSign(privateKey);
            sig.update(data);

            byte[] signature = sig.sign();

            Signature ver = Signature.getInstance(publicKeyAlgorithm);
            ver.initVerify(publicKey);
            ver.update(data);

            return ver.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    private PrivateKey loadPrivateKey(String encodedPrivateKey, String passphrase) throws CertificateException {
        PrivateKey privateKey = null;
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(encodedPrivateKey.getBytes())))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            Object object = pemParser.readObject();

            if (object instanceof PEMEncryptedKeyPair) {
                PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(passphrase.toCharArray());
                KeyPair keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
                privateKey = keyPair.getPrivate();
            } else if (object instanceof PEMKeyPair) {
                KeyPair keyPair = converter.getKeyPair((PEMKeyPair) object);
                privateKey = keyPair.getPrivate();
            } else if (object instanceof PrivateKeyInfo) {
                PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) object;
                privateKey = converter.getPrivateKey(privateKeyInfo);
            }
        } catch (IOException ex) {
            throw new CertificateException("Failed to read private key.", ex);
        }

        if (privateKey == null) {
            throw new CertificateException("Failed to read private key. The security provider could not parse it.");
        }

        return privateKey;
    }

    private X509Certificate loadCertificate(String encodedCertificate) throws CertificateException {
        X509Certificate certificate;

        try (PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(encodedCertificate.getBytes())))) {
            Object object = pemParser.readObject();
            if (object instanceof X509CertificateHolder) {
                certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder) object);
            } else {
                throw new CertificateException("Unsupported certificate type, not an X509CertificateHolder.");
            }
        } catch (IOException ex) {
            throw new CertificateException("Failed to read certificate.", ex);
        }

        if (certificate == null) {
            throw new CertificateException("Failed to read certificate. The security provider could not parse it.");
        }

        return certificate;
    }
}
