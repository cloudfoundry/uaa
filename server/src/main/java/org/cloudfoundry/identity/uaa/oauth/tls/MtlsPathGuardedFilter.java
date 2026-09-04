package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;

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
            delegate.doFilter(request, response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }
}
