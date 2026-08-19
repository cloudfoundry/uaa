/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.test.network;

import com.sun.net.httpserver.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.http.HttpHeaders;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;

import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.cloudfoundry.identity.uaa.util.SocketUtils.getSelfCertificate;

public class NetworkTestUtils {
    static final String commonName = "localhost";
    static final String organizationalUnit = "UAA";
    static final String organization = "Pivotal Software";
    static final String city = "San Francisco";
    static final String state = "CA";
    static final String country = "UA";
    static final String alias = "uaa-test-cert";
    public static final String keyPass = "password";

    static RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private static final AtomicLong serialNumbers = new AtomicLong();

    public static File getKeystore(Date issueDate,
            long validityDays) throws Exception {
        File directory = new File(System.getProperty("java.io.tmpdir"));
        String filename = generator.generate() + ".jks";
        return getKeystore(directory, filename, issueDate, validityDays);
    }

    public static File getKeystore(File directory,
            String filename,
            Date issueDate,
            long validityDays) throws Exception {
        return getKeystore(directory,
                filename,
                4096,
                commonName,
                organizationalUnit,
                organization,
                issueDate,
                validityDays,
                alias,
                keyPass);
    }

    public static File getKeystore(File directory,
            String filename,
            int keysize,
            String commonName,
            String organizationalUnit,
            String organization,
            Date issueDate,
            long validityDays,
            String keyAlias,
            String keyPass) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keysize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X509Certificate[] chain = {getSelfCertificate(keyPair, organization, organizationalUnit, commonName, issueDate, validityDays * 24 * 60 * 60, "SHA256withRSA")};
        keyStore.setKeyEntry(keyAlias, keyPair.getPrivate(), keyPass.toCharArray(), chain);

        File keystore = new File(directory, filename);
        if (!keystore.createNewFile()) {
            throw new FileNotFoundException("Unable to create file:" + keystore);
        }
        keyStore.store(new FileOutputStream(keystore, false), keyPass.toCharArray());
        return keystore;
    }

    /**
     * A keystore whose single key entry holds a full leaf -&gt; intermediate -&gt; root certificate
     * chain. The individual certificates are exposed so tests can assert on the chain or feed the
     * root to a trust store.
     */
    public record ChainedKeystore(File file,
            X509Certificate rootCertificate,
            X509Certificate intermediateCertificate,
            X509Certificate leafCertificate) {
    }

    /**
     * Builds a keystore containing a three-certificate chain (leaf -&gt; intermediate -&gt; root) for
     * {@code localhost}, in contrast to {@link #getKeystore(Date, long)}, which produces a single
     * self-signed certificate. A server started with this presents all three certificates during
     * the TLS handshake, the way a real identity provider behind a CA hierarchy does.
     * <p>
     * This distinction matters: a trust strategy that keys off {@code chain.length == 1} behaves
     * completely differently against this keystore than against the single-certificate one.
     */
    public static ChainedKeystore getChainedKeystore(Date issueDate, long validityDays) throws Exception {
        Security.addProvider(new BouncyCastleFipsProvider());

        long validForSeconds = validityDays * 24 * 60 * 60;

        KeyPair rootKeyPair = generateKeyPair();
        KeyPair intermediateKeyPair = generateKeyPair();
        KeyPair leafKeyPair = generateKeyPair();

        X500Name rootName = distinguishedName("UAA Test Root CA");
        X500Name intermediateName = distinguishedName("UAA Test Intermediate CA");
        X500Name leafName = distinguishedName(commonName);

        X509Certificate root = issueCertificate(rootName, rootKeyPair.getPublic(),
                rootName, rootKeyPair.getPrivate(), issueDate, validForSeconds, true, null);
        X509Certificate intermediate = issueCertificate(intermediateName, intermediateKeyPair.getPublic(),
                rootName, rootKeyPair.getPrivate(), issueDate, validForSeconds, true, null);
        X509Certificate leaf = issueCertificate(leafName, leafKeyPair.getPublic(),
                intermediateName, intermediateKeyPair.getPrivate(), issueDate, validForSeconds, false, commonName);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry(alias, leafKeyPair.getPrivate(), keyPass.toCharArray(),
                new X509Certificate[]{leaf, intermediate, root});

        File keystoreFile = new File(System.getProperty("java.io.tmpdir"), generator.generate() + ".jks");
        if (!keystoreFile.createNewFile()) {
            throw new FileNotFoundException("Unable to create file:" + keystoreFile);
        }
        try (FileOutputStream out = new FileOutputStream(keystoreFile, false)) {
            keyStore.store(out, keyPass.toCharArray());
        }

        return new ChainedKeystore(keystoreFile, root, intermediate, leaf);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static X500Name distinguishedName(String cn) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.OU, organizationalUnit);
        builder.addRDN(BCStyle.O, organization);
        builder.addRDN(BCStyle.CN, cn);
        return builder.build();
    }

    private static X509Certificate issueCertificate(X500Name subject, PublicKey subjectPublicKey,
            X500Name issuer, PrivateKey issuerPrivateKey,
            Date issueDate, long validForSeconds,
            boolean certificateAuthority, String dnsSubjectAltName) throws Exception {
        Date notAfter = Date.from(issueDate.toInstant().plusSeconds(validForSeconds));
        JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(issuer,
                BigInteger.valueOf(serialNumbers.incrementAndGet()), issueDate, notAfter, subject, subjectPublicKey);

        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(certificateAuthority));
        certGen.addExtension(Extension.keyUsage, true, certificateAuthority
                ? new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
                : new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        if (dnsSubjectAltName != null) {
            certGen.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, dnsSubjectAltName)));
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME).build(issuerPrivateKey);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME).getCertificate(certGen.build(signer));
    }

    public static HttpServer startHttpServer(HttpHandler handler) throws Exception {
        //some stack overflow goodness for testing only
        InetSocketAddress address = new InetSocketAddress(0);
        HttpServer httpServer = HttpServer.create(address, 0);
        httpServer.createContext("/", handler);
        httpServer.setExecutor(new ThreadPoolExecutor(1, 1, 10, TimeUnit.SECONDS, new LinkedBlockingQueue<>()));
        httpServer.start();
        return httpServer;
    }

    public static HttpsServer startHttpsServer(File keystore, String keypass, HttpHandler handler) throws Exception {
        //some stack overflow goodness for testing only
        InetSocketAddress address = new InetSocketAddress(0);
        HttpsServer httpsServer = HttpsServer.create(address, 0);
        SSLContext sslContext = SSLContext.getInstance("TLS");

        char[] password = keypass.toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(keystore);
        ks.load(fis, password);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, password);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);

        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            public void configure(HttpsParameters params) {
                try {
                    SSLContext c = SSLContext.getDefault();
                    SSLEngine engine = c.createSSLEngine();
                    params.setNeedClientAuth(false);
                    params.setCipherSuites(engine.getEnabledCipherSuites());
                    params.setProtocols(engine.getEnabledProtocols());
                    SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                    params.setSSLParameters(defaultSSLParameters);

                } catch (Exception ex) {
                    throw new IllegalStateException(ex);
                }
            }
        });
        httpsServer.createContext("/", handler);
        httpsServer.setExecutor(new ThreadPoolExecutor(1, 1, 10, TimeUnit.SECONDS, new LinkedBlockingQueue<>()));
        httpsServer.start();
        return httpsServer;
    }

    public static class SimpleHttpResponseHandler implements HttpHandler {

        private final HttpHeaders headers;
        private final String responseBody;
        private volatile boolean wasInvoked;

        public SimpleHttpResponseHandler(HttpHeaders headers, String responseBody) {
            this.headers = headers;
            this.responseBody = responseBody;
        }

        public boolean wasInvoked() {
            return wasInvoked;
        }

        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            wasInvoked = true;
            HttpsExchange exchange = (HttpsExchange) httpExchange;
            headers.forEach((key, values) -> {
                for (String value : values) {
                    exchange.getResponseHeaders().add(key, value);
                }
            });
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, responseBody.length());
            OutputStream os = exchange.getResponseBody();
            os.write(responseBody.getBytes());
            os.flush();
            os.close();
            httpExchange.close();
        }
    }
}
