package org.cloudfoundry.identity.uaa.util;

import lombok.Getter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.cloudfoundry.identity.uaa.saml.SamlKey;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.cloudfoundry.identity.uaa.oauth.jwt.JwtAlgorithms.DEFAULT_RSA;

@Getter
public class KeyWithCert {
    private final X509Certificate certificate;
    private final PrivateKey privateKey;

    public KeyWithCert(String encodedCertificate) throws CertificateException {
        certificate = loadCertificate(encodedCertificate);
        privateKey = null;
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

    public static KeyWithCert fromSamlKey(SamlKey samlKey) throws CertificateException {
        if (samlKey == null) {
            return null;
        }

        if (samlKey.getKey() == null) {
            return new KeyWithCert(samlKey.getCertificate());
        }

        return new KeyWithCert(samlKey.getKey(), samlKey.getPassphrase(), samlKey.getCertificate());
    }

    private boolean keysMatch(PublicKey publicKey, PrivateKey privateKey) {
        byte[] data = {42};

        String privateKeyAlgorithm = getJavaAlgorithm(privateKey.getAlgorithm());
        String publicKeyAlgorithm = getJavaAlgorithm(publicKey.getAlgorithm());

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

    private static String getJavaAlgorithm(String publicKeyAlgorithm) {
        if ("EC".equals(publicKeyAlgorithm)) {
            publicKeyAlgorithm = "ECDSA";
        } else if ("RSA".equals(publicKeyAlgorithm)) {
            publicKeyAlgorithm = DEFAULT_RSA;
        }
        return publicKeyAlgorithm;
    }

    private static PrivateKey loadPrivateKey(String encodedPrivateKey, String passphrase) throws CertificateException {
        PrivateKey privateKey = null;
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(encodedPrivateKey.getBytes())))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleFipsProvider.PROVIDER_NAME);

            Object object = pemParser.readObject();

            if (object instanceof PEMEncryptedKeyPair pemEncryptedKeyPair) {
                PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(passphrase.toCharArray());
                KeyPair keyPair = converter.getKeyPair(pemEncryptedKeyPair.decryptKeyPair(decProv));
                privateKey = keyPair.getPrivate();
            } else if (object instanceof PEMKeyPair pemKeyPair) {
                KeyPair keyPair = converter.getKeyPair(pemKeyPair);
                privateKey = keyPair.getPrivate();
            } else if (object instanceof PrivateKeyInfo privateKeyInfo) {
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

    private static X509Certificate loadCertificate(String encodedCertificate) throws CertificateException {
        X509Certificate certificate;

        try (PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(encodedCertificate.getBytes())))) {
            Object object = pemParser.readObject();
            if (object instanceof X509CertificateHolder x509CertificateHolder) {
                certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleFipsProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
            } else {
                throw new CertificateException("Unsupported certificate type, not an X509CertificateHolder.");
            }
        } catch (Exception ex) {
            throw new CertificateException("Failed to read certificate.", ex);
        }

        if (certificate == null) {
            throw new CertificateException("Failed to read certificate. The security provider could not parse it.");
        }

        return certificate;
    }

    public String getEncodedCertificate() throws CertificateEncodingException {
        return new String(Base64.getEncoder().encode(certificate.getEncoded()));
    }
}
