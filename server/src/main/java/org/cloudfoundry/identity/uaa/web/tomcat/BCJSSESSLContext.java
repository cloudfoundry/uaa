package org.cloudfoundry.identity.uaa.web.tomcat;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.apache.tomcat.util.net.SSLContext;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * A Tomcat {@link SSLContext} backed by the FIPS Bouncy Castle JSSE provider (BCJSSE). Mirrors Tomcat's
 * own (package-private) {@code JSSESSLContext} but sources the underlying {@code javax.net.ssl.SSLContext}
 * from the registered {@link BouncyCastleJsseProvider} instead of the default (SunJSSE) provider.
 *
 * <p>This is what lets the {@code uaa.mtls-enabled} connector both negotiate TLS 1.3 and request an
 * optional client certificate: unlike SunJSSE (which sends no {@code CertificateRequest} under TLS 1.3,
 * JDK-8206923), BCJSSE sends an in-handshake TLS 1.3 {@code CertificateRequest}.
 *
 * <p>Requires {@link MtlsClientAuthTomcatCustomizer#ensureJsseProviderRegistered()} to have run, so that
 * the {@code BCJSSE} provider is registered.
 */
public final class BCJSSESSLContext implements SSLContext {

    private final javax.net.ssl.SSLContext context;
    private KeyManager[] kms;
    private TrustManager[] tms;

    public BCJSSESSLContext(String protocol) throws NoSuchAlgorithmException {
        Provider provider = Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        if (provider == null) {
            throw new NoSuchAlgorithmException(
                    "The " + BouncyCastleJsseProvider.PROVIDER_NAME + " provider is not registered; "
                            + "call MtlsClientAuthTomcatCustomizer.ensureJsseProviderRegistered() before "
                            + "building the connector SSLContext");
        }
        this.context = javax.net.ssl.SSLContext.getInstance(protocol, provider);
    }

    @Override
    public void init(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        this.kms = kms;
        this.tms = tms;
        context.init(kms, tms, sr);
    }

    @Override
    public void destroy() {
        // No-op, matching Tomcat's JSSESSLContext.
    }

    @Override
    public SSLSessionContext getServerSessionContext() {
        return context.getServerSessionContext();
    }

    @Override
    public SSLEngine createSSLEngine() {
        return context.createSSLEngine();
    }

    @Override
    public SSLServerSocketFactory getServerSocketFactory() {
        return context.getServerSocketFactory();
    }

    @Override
    public SSLParameters getSupportedSSLParameters() {
        return context.getSupportedSSLParameters();
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        X509Certificate[] result = null;
        if (kms != null) {
            for (int i = 0; i < kms.length && result == null; i++) {
                if (kms[i] instanceof X509KeyManager) {
                    result = ((X509KeyManager) kms[i]).getCertificateChain(alias);
                }
            }
        }
        return result;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        Set<X509Certificate> certs = new HashSet<>();
        if (tms != null) {
            for (TrustManager tm : tms) {
                if (tm instanceof X509TrustManager) {
                    X509Certificate[] accepted = ((X509TrustManager) tm).getAcceptedIssuers();
                    certs.addAll(Arrays.asList(accepted));
                }
            }
        }
        return certs.toArray(new X509Certificate[0]);
    }
}
