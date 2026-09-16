package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Makes {@code /oauth/mtls/token} behave as a non-existent path on deployments that have not enabled
 * RFC 8705 mutual-TLS client authentication ({@code uaa.mtls-enabled}, false by default).
 *
 * <p>The feature is otherwise gated asymmetrically: {@code mtlsTokenEndpointSecurity} is
 * {@code @ConditionalOnProperty}, but {@code UaaTokenEndpoint}'s {@code @RequestMapping} lists the
 * path unconditionally. With the feature off, no OAuth filter chain has a {@code securityMatcher} for
 * it, so the request fell through to the catch-all {@code uiSecurity} chain -- form login, session,
 * CSRF -- and was answered by that chain's {@code CsrfFilter} with
 * {@code 403 "Could not verify the provided CSRF token"}. That is a closed door, but an accidental
 * one: it depends on CSRF rather than on any decision about this feature, and it leaves the token
 * endpoint reachable behind the browser login chain, where the authenticated principal is a user
 * rather than a client.
 *
 * <p>Runs at order -290: after {@code ZonePathContextRewritingFilter}
 * ({@code Ordered.HIGHEST_PRECEDENCE + 1}), so the servlet path has already had any
 * {@code /z/{subdomain}} prefix stripped and a zone-path request is matched the same as a direct one;
 * and before Spring Security's filter (-100), so the path never reaches a filter chain at all.
 *
 * <p>This filter only ever denies. It cannot grant access that would otherwise be refused: when
 * {@code uaa.mtls-enabled} is true it is a pass-through, and every other path is untouched.
 */
public class MtlsEndpointAvailabilityFilter implements Filter {

    private final boolean mtlsEnabled;

    public MtlsEndpointAvailabilityFilter(boolean mtlsEnabled) {
        this.mtlsEnabled = mtlsEnabled;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        if (!mtlsEnabled && RawPeerCertificateCaptureFilter.isMtlsTokenPath(httpRequest.getServletPath())) {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        chain.doFilter(request, response);
    }
}
