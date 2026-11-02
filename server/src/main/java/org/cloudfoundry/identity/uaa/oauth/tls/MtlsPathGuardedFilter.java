package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Wraps a delegate {@link Filter} so it only runs for requests whose effective (post
 * {@code ZonePathContextRewritingFilter}) servlet path is {@code /oauth/mtls/token/**} -- see
 * {@link RawPeerCertificateCaptureFilter#isMtlsTokenPath(HttpServletRequest)}.
 *
 * <p>Used in {@code SpringServletXmlFiltersConfiguration} to scope the third-party, package-private
 * {@code ClientCertificateMapper} filter to the mTLS token endpoint without relying on a container
 * URL-pattern registration. A URL-pattern registration is matched against the request's original,
 * pre-rewrite URI, so it would not include the filter in the chain for a zone-path-prefixed mTLS
 * request (e.g. {@code /z/{subdomain}/oauth/mtls/token}), even though downstream code (including this
 * guard) sees the same effective path as a direct request.
 */
public class MtlsPathGuardedFilter implements Filter {

    private final Filter delegate;

    public MtlsPathGuardedFilter(Filter delegate) {
        this.delegate = delegate;
    }

    Filter getDelegate() {
        return delegate;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (RawPeerCertificateCaptureFilter.isMtlsTokenPath((HttpServletRequest) request)) {
            Object originalCertificate = request.getAttribute("jakarta.servlet.request.X509Certificate");
            AtomicBoolean downstreamStarted = new AtomicBoolean();
            try {
                delegate.doFilter(request, response, (mappedRequest, mappedResponse) -> {
                    downstreamStarted.set(true);
                    chain.doFilter(mappedRequest, mappedResponse);
                });
            } catch (IllegalArgumentException e) {
                if (downstreamStarted.get()) {
                    // Application exceptions must propagate, rather than rerunning the handler.
                    throw e;
                }
                // The mapper contains certificate parsing errors but not URL-decoding errors. Treat
                // malformed XFCC the same way: preserve the TLS peer and let authentication decide.
                // Proxy-only clients reject the unchanged attribute; direct clients use the raw peer.
                request.setAttribute("jakarta.servlet.request.X509Certificate", originalCertificate);
                chain.doFilter(request, response);
            }
        } else {
            chain.doFilter(request, response);
        }
    }
}
