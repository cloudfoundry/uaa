package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import java.io.IOException;

/**
 * Captures the genuine TLS-handshake peer certificate before the downstream {@code ClientCertificateMapper}
 * filter has a chance to overwrite it.
 *
 * <p>With {@code certificateVerification=optionalNoCA} configured on the servlet container, the container
 * populates the standard {@code jakarta.servlet.request.X509Certificate} request attribute with whatever
 * certificate the immediate TLS peer actually presented during the handshake (e.g. the Gorouter's
 * {@code gorouter_backend_tls} client cert). The {@code ClientCertificateMapper} filter (registered at
 * order -200 in {@code SpringServletXmlFiltersConfiguration}) later overwrites that same attribute with a
 * certificate it decodes from the {@code X-Forwarded-Client-Cert} header whenever that header is present,
 * discarding the genuine handshake value.
 *
 * <p>This filter must be registered to run <em>before</em> {@code ClientCertificateMapper} so that the
 * genuine peer certificate is preserved in a dedicated attribute
 * ({@link #RAW_PEER_CERTIFICATE_ATTRIBUTE}). This is what allows
 * {@link TlsClientAuthentication#isCertificateFromTrustedProxy(org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration)}
 * to validate "what the immediate TLS peer actually presented" (this attribute) against a specific
 * client's configured {@code tls-client-auth-trusted-proxy-ca}, confirming the
 * {@code X-Forwarded-Client-Cert} header was genuinely set by a trusted proxy (e.g. the Gorouter)
 * rather than a direct caller spoofing it -- the actual value returned to callers (e.g. via
 * {@link TlsClientAuthentication#getCertificateFromRequest(org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration)})
 * still comes from the standard, XFCC-derived {@code jakarta.servlet.request.X509Certificate}
 * attribute -- this filter's captured value is used only for the trust check, never as the
 * authenticated client certificate itself.
 */
public class RawPeerCertificateCaptureFilter implements Filter {

    public static final String RAW_PEER_CERTIFICATE_ATTRIBUTE =
            "org.cloudfoundry.identity.uaa.oauth.tls.rawPeerCertificate";

    private static final String X509_CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        request.setAttribute(RAW_PEER_CERTIFICATE_ATTRIBUTE, request.getAttribute(X509_CERTIFICATE_ATTRIBUTE));
        chain.doFilter(request, response);
    }
}
