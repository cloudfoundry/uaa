package org.cloudfoundry.identity.uaa.spiffe;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

/** Test-only helper that mints a CA and Diego-style instance certificates. */
public final class SpiffeTestCerts {

    static {
        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleFipsProvider());
        }
    }

    private SpiffeTestCerts() {
    }

    /** A certificate together with the key pair whose public key it certifies. */
    public record CertKey(X509Certificate certificate, KeyPair keyPair) {
    }

    public static KeyPair newRsaKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
            kpg.initialize(2048);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Self-signed CA usable as the configured instance-identity CA. */
    public static CertKey newCa() {
        KeyPair caKeys = newRsaKeyPair();
        X500Name caName = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "instanceIdentityCA")
                .build();
        X509Certificate cert = sign(caName, caName, caKeys.getPublic(), caKeys.getPrivate(),
                Instant.now().minus(1, ChronoUnit.DAYS), Instant.now().plus(365, ChronoUnit.DAYS));
        return new CertKey(cert, caKeys);
    }

    /** Instance cert signed by {@code ca}, with org/space/app OUs in one multi-valued RDN. */
    public static CertKey newInstanceCert(CertKey ca, String orgId, String spaceId, String appId) {
        return newInstanceCert(ca, orgId, spaceId, appId,
                Instant.now().minus(1, ChronoUnit.HOURS), Instant.now().plus(1, ChronoUnit.HOURS));
    }

    public static CertKey newInstanceCert(CertKey ca, String orgId, String spaceId, String appId,
                                          Instant notBefore, Instant notAfter) {
        KeyPair leafKeys = newRsaKeyPair();
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addMultiValuedRDN(
                        new ASN1ObjectIdentifier[]{BCStyle.OU, BCStyle.OU, BCStyle.OU},
                        new String[]{"organization:" + orgId, "space:" + spaceId, "app:" + appId})
                .addRDN(BCStyle.CN, "instance-" + appId)
                .build();
        X500Name issuer = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "instanceIdentityCA")
                .build();
        X509Certificate cert = sign(issuer, subject, leafKeys.getPublic(), ca.keyPair().getPrivate(),
                notBefore, notAfter);
        return new CertKey(cert, leafKeys);
    }

    public static String pkcs8PrivateKeyPem(PrivateKey privateKey) {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(privateKey.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
    }

    public static String certificatePem(X509Certificate certificate) {
        try {
            String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded());
            return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n";
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate sign(X500Name issuer, X500Name subject,
                                        java.security.PublicKey subjectPublicKey, PrivateKey issuerPrivateKey,
                                        Instant notBefore, Instant notAfter) {
        try {
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer,
                    BigInteger.valueOf(System.nanoTime()),
                    Date.from(notBefore),
                    Date.from(notAfter),
                    subject,
                    subjectPublicKey);
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                    .build(issuerPrivateKey);
            X509CertificateHolder holder = builder.build(signer);
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                    .getCertificate(holder);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
