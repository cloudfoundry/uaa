package org.cloudfoundry.identity.uaa.web.tomcat;

import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

import java.security.Provider;
import java.security.Security;

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
 * <p>Uses the FIPS Bouncy Castle JSSE provider (BCJSSE) for this connector. OpenJDK's JSSE never
 * implemented server-side TLS 1.3 client authentication (JDK-8206923): requesting a client certificate
 * without requiring/validating it against a CA ({@code certificateVerification=optionalNoCA}, or Tomcat's
 * {@code optional} mode) relies on requesting the certificate again via post-handshake authentication
 * (PHA), which JSSE's TLS 1.3 implementation does not support -- and on at least one JDK build the server
 * silently never sends a {@code CertificateRequest} at all under TLS 1.3, silently defeating this feature.
 * BCJSSE implements TLS 1.3 client authentication in-handshake, so the connector can offer TLS 1.3 again
 * (reverting this PR's earlier {@code all,-TLSv1.3} pin and restoring the pre-PR {@code TLSv1.2,TLSv1.3}
 * protocol set). The BCJSSE provider is registered idempotently, and the connector's protocol handler is
 * pointed at {@link BCJSSESslImplementation} via {@code sslImplementationName} so that only this connector
 * uses BCJSSE; all other JVM TLS stays on the default provider.
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
        ensureJsseProviderRegistered();
        factory.addConnectorCustomizers(connector -> {
            if (!(connector.getProtocolHandler() instanceof AbstractHttp11Protocol<?> protocol)) {
                throw new IllegalStateException(
                        "uaa.mtls-enabled requires an HTTP/1.1 Tomcat connector (got "
                                + connector.getProtocolHandler().getClass().getName()
                                + "); cannot install BCJSSESslImplementation for TLS 1.3 client-cert support");
            }
            protocol.setSslImplementationName(BCJSSESslImplementation.class.getName());
            for (SSLHostConfig sslHostConfig : connector.findSslHostConfigs()) {
                sslHostConfig.setCertificateVerification("optionalNoCA");
                sslHostConfig.setTrustManagerClassName(NoAcceptedIssuersTrustManager.class.getName());
            }
        });
    }

    /**
     * Registers the FIPS Bouncy Castle provider ({@code BCFIPS}) and the FIPS Bouncy Castle JSSE
     * provider ({@code BCJSSE}) idempotently, if not already present. Registering the low-level
     * crypto provider first is required: {@code BouncyCastleJsseProvider} built in FIPS mode binds
     * to it, which is what makes {@code SSLContext.getInstance("TLS", "BCJSSE")} usable (and is what
     * supplies FIPS-compliant {@code SecureRandom}s for the TLS handshake).
     *
     * <p>If a provider is already registered under the {@code BCJSSE} name -- e.g. via the JVM's
     * {@code java.security} configuration file, or some other library -- its mere presence is not
     * sufficient: it must genuinely be a FIPS-mode {@link BouncyCastleJsseProvider}, or this connector's
     * promised FIPS guarantee (documented on this class) would be silently defeated. Fails fast with
     * {@link IllegalStateException} rather than silently proceeding with a wrong/non-FIPS provider.
     *
     * @throws IllegalStateException if a provider already registered under the {@code BCJSSE} name is
     *         not a {@link BouncyCastleJsseProvider}, or is one but not in FIPS mode
     */
    static void ensureJsseProviderRegistered() {
        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleFipsProvider());
        }
        Provider existingJsseProvider = Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        if (existingJsseProvider == null) {
            Security.addProvider(new BouncyCastleJsseProvider(true,
                    Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME)));
            return;
        }
        if (!(existingJsseProvider instanceof BouncyCastleJsseProvider bcJsseProvider)) {
            throw new IllegalStateException(
                    "uaa.mtls-enabled requires the FIPS BouncyCastleJsseProvider registered under the name '"
                            + BouncyCastleJsseProvider.PROVIDER_NAME
                            + "', but a different provider is already registered under that name: "
                            + existingJsseProvider.getClass().getName()
                            + " -- refusing to silently proceed without the promised FIPS guarantee");
        }
        if (!bcJsseProvider.isFipsMode()) {
            throw new IllegalStateException(
                    "uaa.mtls-enabled requires the FIPS BouncyCastleJsseProvider registered under the name '"
                            + BouncyCastleJsseProvider.PROVIDER_NAME
                            + "', and a " + BouncyCastleJsseProvider.class.getName()
                            + " is indeed registered under that name, but it was not constructed in FIPS mode"
                            + " -- refusing to silently proceed without the promised FIPS guarantee");
        }
    }
}
