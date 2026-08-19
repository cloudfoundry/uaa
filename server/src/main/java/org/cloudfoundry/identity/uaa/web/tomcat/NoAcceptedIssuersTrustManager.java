package org.cloudfoundry.identity.uaa.web.tomcat;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

/**
 * A {@link X509TrustManager} used by {@link MtlsClientAuthTomcatCustomizer} to make the mTLS
 * connector advertise no acceptable-issuer constraint in the TLS {@code CertificateRequest}
 * handshake message, while performing no certificate validation at the TLS layer at all -- the trust
 * decision is deferred entirely to per-client application logic in
 * {@link org.cloudfoundry.identity.uaa.oauth.tls.TlsClientAuthentication}.
 *
 * <p>Must be a public, top-level class with a public no-arg constructor: Tomcat instantiates trust
 * manager classes configured via {@code SSLHostConfig#setTrustManagerClassName(String)} via
 * reflection ({@code Class#getConstructor()} / {@code Constructor#newInstance()}), which requires
 * exactly that shape.
 *
 * <p>An empty accepted-issuers list is not merely "no restriction is enforced" -- it changes what
 * Tomcat/JSSE actually puts on the wire. Even with {@code certificateVerification=optionalNoCA} (which
 * only disables validation), Tomcat still populates the handshake's "certificate_authorities" field
 * from whatever trust store/trust manager is configured, and absent one, JSSE falls back to the JVM's
 * default {@code cacerts} (a long list of unrelated public root CAs). Well-behaved TLS clients --
 * including Go's {@code crypto/tls}, used by the real Gorouter -- select which certificate (if any) to
 * present by matching its issuer against that advertised list, and send an <em>empty</em> Certificate
 * message if nothing matches, per the TLS spec -- silently withholding a legitimate client certificate
 * whose CA simply isn't a public root CA. An empty accepted-issuers list here means "any CA is
 * acceptable" on the wire, so such clients present whatever certificate they have configured.
 *
 * @see MtlsClientAuthTomcatCustomizer
 */
public final class NoAcceptedIssuersTrustManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
        // No-op: TLS-layer client certificate validation is intentionally disabled
        // (certificateVerification=optionalNoCA on the connector). Proof of private-key possession
        // still happens as part of the handshake itself; the trust decision (which CA, if any, is
        // acceptable for a given client) is deferred entirely to per-client application logic.
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // Not used: this trust manager is installed on a server-side connector to evaluate
        // certificates presented BY clients, not to validate a server certificate.
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
