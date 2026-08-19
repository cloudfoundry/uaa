package org.cloudfoundry.identity.uaa.web.tomcat;

import org.apache.tomcat.util.net.SSLHostConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

/**
 * When {@code uaa.mtls-enabled} is true, configures the embedded Tomcat connector to request a client
 * certificate during the TLS handshake without validating it against any CA at the TLS layer
 * ({@code certificateVerification=optionalNoCA}) -- proof of private-key possession still happens as
 * part of the handshake itself, but the trust decision (which CA, if any, is acceptable) is deferred
 * entirely to per-client application logic in {@link org.cloudfoundry.identity.uaa.oauth.tls.TlsClientAuthentication}.
 *
 * <p>This is deliberately different from Spring Boot's own {@code server.ssl.client-auth} property,
 * which only supports Tomcat's {@code none}/{@code optional}/{@code required} verification levels --
 * not {@code optionalNoCA}. A static, deploy-time CA truststore was considered and rejected: it would
 * need to be kept in sync with whatever CA(s) are configured per-client at runtime via the client-admin
 * API, which is an operational hazard.
 *
 * <p>Also disables TLSv1.3 on this connector ({@code protocols="all,-TLSv1.3"}). This works around a
 * real, confirmed limitation of JSSE's TLS 1.3 implementation: requesting a client certificate
 * without also requiring/validating it against a CA (i.e. {@code optionalNoCA}, or Tomcat's other
 * {@code optional} mode) relies on the server being able to request the certificate again later via
 * post-handshake authentication (PHA) if it wasn't sent upfront -- and JSSE's TLS 1.3 implementation
 * does not support PHA (Tomcat itself logs this exact incompatibility at startup:
 * "The JSSE TLS 1.3 implementation does not support post handshake authentication (PHA) and is
 * therefore incompatible with optional certificate authentication"). In practice, on at least one real
 * JDK build this means the server silently never sends a {@code CertificateRequest} at all under TLS
 * 1.3, so no client certificate -- trusted or not -- is ever captured, silently defeating this entire
 * feature. Confirmed empirically against a live deployment via {@code openssl s_client}: {@code -tls1_2}
 * receives a {@code CertificateRequest}; {@code -tls1_3} does not. Restricting this connector to
 * TLSv1.2 is Tomcat's own documented workaround for this exact incompatibility.
 *
 * <p>Also installs a custom {@link NoAcceptedIssuersTrustManager} on the connector, via
 * {@code SSLHostConfig#setTrustManagerClassName(String)}. Even with {@code optionalNoCA} (which
 * disables certificate <em>validation</em>), Tomcat/JSSE still populates the
 * {@code CertificateRequest} handshake message's "certificate_authorities" field from whatever trust
 * store/trust manager is configured on the connector -- and absent an explicit one, JSSE falls back to
 * the JVM's default {@code cacerts} (a large list of public root CAs, e.g. DigiCert, Let's Encrypt,
 * etc.), none of which sign any real client's mTLS certificate here. Well-behaved TLS clients --
 * including Go's {@code crypto/tls}, used by the real Gorouter -- select which certificate (if any) to
 * present by matching its issuer against that advertised list, and send an <em>empty</em> Certificate
 * message if nothing matches, per the TLS spec. Confirmed empirically against a live deployment:
 * {@code openssl s_client}'s "Acceptable client certificate CA names" output listed only unrelated
 * public root CAs, never {@code service_cf_internal_ca} (the CA that signs the Gorouter's own backend
 * mTLS certificate) -- and packet capture confirmed the Gorouter's actual backend connection sent a
 * zero-length certificate_list in response, silently defeating this entire feature. An empty trust
 * store was tried first but rejected: Tomcat's PKIX-based trust manager path
 * ({@code TrustManagerFactory}'s default algorithm on at least one JDK build) throws
 * {@code InvalidAlgorithmParameterException: the trustAnchors parameter must be non-empty} for an
 * empty {@link java.security.KeyStore} -- PKIX fundamentally requires at least one trust anchor.
 * {@link NoAcceptedIssuersTrustManager} sidesteps that entirely by bypassing the KeyStore/algorithm
 * path via Tomcat's {@code trustManagerClassName} extension point, advertising no acceptable-issuer
 * constraint at all -- consistent with this customizer's overall design of deferring the trust
 * decision entirely to per-client application logic.
 *
 * <p>Runs after Spring Boot's own SSL connector configuration so it can override the already-configured
 * {@link SSLHostConfig}(s) on the connector.
 */
@Component
public class MtlsClientAuthTomcatCustomizer implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

    private final boolean mtlsEnabled;

    public MtlsClientAuthTomcatCustomizer(@Value("${uaa.mtls-enabled:false}") boolean mtlsEnabled) {
        this.mtlsEnabled = mtlsEnabled;
    }

    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        if (!mtlsEnabled) {
            return;
        }
        factory.addConnectorCustomizers(connector -> {
            for (SSLHostConfig sslHostConfig : connector.findSslHostConfigs()) {
                sslHostConfig.setCertificateVerification("optionalNoCA");
                sslHostConfig.setProtocols("all,-TLSv1.3");
                sslHostConfig.setTrustManagerClassName(NoAcceptedIssuersTrustManager.class.getName());
            }
        });
    }
}
