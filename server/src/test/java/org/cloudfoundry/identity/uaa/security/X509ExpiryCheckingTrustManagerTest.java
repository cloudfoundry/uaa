/*
 *********************************************************************************
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
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.concurrent.CompletableFuture;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class X509ExpiryCheckingTrustManagerTest {

    @Test
    void checkServerTrusted_throwsExceptionWhenCertIsExpired() throws Exception {
        X509ExpiryCheckingTrustManager manager = new X509ExpiryCheckingTrustManager();
        X509TrustManager mockedDelegate = Mockito.mock(X509TrustManager.class);
        manager.setDelegate(mockedDelegate);
        X509Certificate certificate = Mockito.mock(X509Certificate.class);
        X509Certificate[] x509Certificates = {certificate};

        doNothing().when(mockedDelegate).checkServerTrusted(x509Certificates, "string");
        doThrow(new CertificateExpiredException()).when(certificate).checkValidity();
        try {
            manager.checkServerTrusted(x509Certificates, "string");
            fail("");
        } catch (CertificateExpiredException _) {
            verify(mockedDelegate).checkServerTrusted(x509Certificates, "string");
            verify(certificate).checkValidity();
        }
    }

    @Test
    void checkClientTrusted_callsDelegate() throws Exception {
        X509ExpiryCheckingTrustManager manager = new X509ExpiryCheckingTrustManager();
        X509TrustManager mockedDelegate = Mockito.mock(X509TrustManager.class);
        manager.setDelegate(mockedDelegate);

        X509Certificate certificate = Mockito.mock(X509Certificate.class);
        X509Certificate[] x509Certificates = {certificate};

        doNothing().when(mockedDelegate).checkClientTrusted(x509Certificates, "string");
        manager.checkClientTrusted(x509Certificates, "string");
        verify(mockedDelegate).checkClientTrusted(x509Certificates, "string");
    }

    @Test
    void checkAcceptedIssuers_callsDelegate() {
        X509ExpiryCheckingTrustManager manager = new X509ExpiryCheckingTrustManager();
        X509TrustManager mockedDelegate = Mockito.mock(X509TrustManager.class);
        manager.setDelegate(mockedDelegate);

        manager.getAcceptedIssuers();
        verify(mockedDelegate).getAcceptedIssuers();
    }

    @Test
    void defaultDelegateIsExtendedSoEndpointIdentificationIsNotLost() {
        assertThat(new X509ExpiryCheckingTrustManager()).isInstanceOf(X509ExtendedTrustManager.class)
                .extracting("delegate").isInstanceOf(X509ExtendedTrustManager.class);
    }

    @Test
    void checkServerTrusted_withSocket_callsExtendedDelegateAndChecksExpiry() throws Exception {
        X509ExpiryCheckingTrustManager manager = new X509ExpiryCheckingTrustManager();
        X509ExtendedTrustManager mockedDelegate = Mockito.mock(X509ExtendedTrustManager.class);
        manager.setDelegate(mockedDelegate);
        X509Certificate certificate = Mockito.mock(X509Certificate.class);
        X509Certificate[] x509Certificates = {certificate};
        Socket socket = Mockito.mock(Socket.class);

        manager.checkServerTrusted(x509Certificates, "RSA", socket);

        verify(mockedDelegate).checkServerTrusted(x509Certificates, "RSA", socket);
        verify(mockedDelegate, never()).checkServerTrusted(x509Certificates, "RSA");
        verify(certificate).checkValidity();
    }

    @Test
    void handshake_withNonExtendedDelegate_failsWhenHostnameDoesNotMatch(@TempDir Path tempDir) throws Exception {
        assertThatThrownBy(() -> handshake(tempDir, "HTTPS", "CN=other.example.com", "san=dns:other.example.com"))
                .hasRootCauseInstanceOf(java.security.cert.CertificateException.class)
                .hasStackTraceContaining("No subject alternative names matching host");
    }

    @Test
    void handshake_withNonExtendedDelegate_succeedsWhenHostnameVerificationNotRequested(@TempDir Path tempDir) throws Exception {
        handshake(tempDir, null, "CN=other.example.com", "san=dns:other.example.com");
    }

    @Test
    void handshake_withNonExtendedDelegate_succeedsWhenHostnameMatches(@TempDir Path tempDir) throws Exception {
        handshake(tempDir, "HTTPS", "CN=localhost", "san=ip:127.0.0.1");
    }

    // Client connects to 127.0.0.1; the non-extended delegate trusts any chain, so only hostname checks can reject
    private static void handshake(Path tempDir, String endpointIdAlgorithm, String dn, String san) throws Exception {
        Path keystore = tempDir.resolve("server.p12");
        Process keytool = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048",
                "-dname", dn, "-ext", san, "-validity", "2",
                "-storetype", "PKCS12", "-keystore", keystore.toString(), "-storepass", "changeit")
                .redirectErrorStream(true).start();
        try (InputStream out = keytool.getInputStream()) {
            out.readAllBytes();
        }
        assertThat(keytool.waitFor()).isZero();

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = java.nio.file.Files.newInputStream(keystore)) {
            ks.load(in, "changeit".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);

        X509ExpiryCheckingTrustManager manager = new X509ExpiryCheckingTrustManager();
        manager.setDelegate(Mockito.mock(X509TrustManager.class));
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(null, new javax.net.ssl.TrustManager[]{manager}, null);

        try (SSLServerSocket server = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<Void> serverSide = CompletableFuture.runAsync(() -> {
                try (SSLSocket s = (SSLSocket) server.accept()) {
                    s.startHandshake();
                } catch (Exception ignored) {
                    // client-side failure is asserted
                }
            });
            try (SSLSocket client = (SSLSocket) clientContext.getSocketFactory()
                    .createSocket(InetAddress.getLoopbackAddress(), server.getLocalPort())) {
                SSLParameters params = client.getSSLParameters();
                params.setEndpointIdentificationAlgorithm(endpointIdAlgorithm);
                client.setSSLParameters(params);
                client.startHandshake();
            } finally {
                serverSide.cancel(true);
            }
        }
    }
}