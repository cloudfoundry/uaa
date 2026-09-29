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
 * Enforces the two endpoint-level policies for {@code /oauth/mtls/token} that have to hold before any
 * authentication runs: it is absent on deployments that have not enabled RFC 8705 mutual-TLS client
 * authentication ({@code uaa.mtls-enabled}, false by default), and it accepts only POST.
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
 * <p>The method restriction lives here rather than in the controller because "method not allowed" is
 * a property of the resource, not of the caller: enforcing it ahead of Spring Security means an
 * unauthenticated GET is answered 405 rather than 401, which is what RFC 9110 calls for, and the
 * {@code Allow} header tells the caller what to do instead. {@code /oauth/token} keeps GET for
 * backwards compatibility and is untouched; the two share a {@code @RequestMapping}, which is how
 * this endpoint inherited GET in the first place. A GET carries the token request in the query
 * string, where access logs and every proxy in front of UAA record it.
 *
 * <p>This filter only ever denies. It cannot grant access that would otherwise be refused: it is a
 * pass-through for POST once the feature is enabled, and every other path is untouched.
 */
public class MtlsEndpointAvailabilityFilter implements Filter {

    private static final String POST = "POST";

    private final boolean mtlsEnabled;

    public MtlsEndpointAvailabilityFilter(boolean mtlsEnabled) {
        this.mtlsEnabled = mtlsEnabled;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        if (!RawPeerCertificateCaptureFilter.isMtlsTokenPath(httpRequest.getServletPath())) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        // Absence is checked first: a disabled endpoint must not disclose which methods it would
        // have accepted.
        if (!mtlsEnabled) {
            httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        if (!POST.equalsIgnoreCase(httpRequest.getMethod())) {
            httpResponse.setHeader("Allow", POST);
            httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }
        chain.doFilter(request, response);
    }
}
