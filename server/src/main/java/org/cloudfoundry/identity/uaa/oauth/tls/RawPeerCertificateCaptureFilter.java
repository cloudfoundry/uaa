package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

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
 *
 * <p>Registered in {@code SpringServletXmlFiltersConfiguration} on the default (all-requests) URL
 * pattern, not a literal {@code /oauth/mtls/token/**} one: {@link #isMtlsTokenPath(HttpServletRequest)} guards
 * this filter's work internally instead, checking the request's <em>effective</em> servlet path (i.e.
 * after {@code ZonePathContextRewritingFilter}, which runs first, has rewritten it). A container
 * URL-pattern registration is matched against the request's original, pre-rewrite URI, so it would
 * never include this filter in the chain for a zone-path-prefixed mTLS request (e.g.
 * {@code /z/{subdomain}/oauth/mtls/token}), even though downstream code sees the same effective path as
 * a direct request.
 */
public class RawPeerCertificateCaptureFilter implements Filter {

    public static final String RAW_PEER_CERTIFICATE_ATTRIBUTE =
            "org.cloudfoundry.identity.uaa.oauth.tls.rawPeerCertificate";

    private static final String X509_CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";
    public static final String MTLS_TOKEN_PATH = "/oauth/mtls/token";
    private static final String MTLS_TOKEN_PATH_PREFIX = MTLS_TOKEN_PATH + "/";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (isMtlsTokenPath((HttpServletRequest) request)) {
            request.setAttribute(RAW_PEER_CERTIFICATE_ATTRIBUTE, request.getAttribute(X509_CERTIFICATE_ATTRIBUTE));
        }
        chain.doFilter(request, response);
    }

    /**
     * Matches the request's effective servlet path -- i.e. after {@code ZonePathContextRewritingFilter}
     * (which runs first in the filter chain) has stripped any {@code /z/{subdomain}} prefix -- against
     * {@code /oauth/mtls/token/**}. Also used by {@link MtlsPathGuardedFilter} to scope the (externally
     * supplied, package-private) {@code ClientCertificateMapper} filter to the same effective path.
     */
    static boolean isMtlsTokenPath(HttpServletRequest request) {
        return isMtlsTokenPath(request.getServletPath());
    }

    public static boolean isMtlsTokenPath(String path) {
        return path != null && (path.equals(MTLS_TOKEN_PATH) || path.startsWith(MTLS_TOKEN_PATH_PREFIX));
    }
}
