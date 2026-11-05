package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;

import java.io.IOException;

/**
 * Runs after zone resolution, before client authentication.
 *
 * <p>The token endpoint accepts only POST. The method is checked after the zone policy, so a zone
 * with mTLS disabled answers 404 regardless of method instead of disclosing what it would accept,
 * and before client authentication, so an unauthenticated GET is answered 405 with {@code Allow}
 * rather than 401 (RFC 9110). {@code /oauth/token} keeps GET for backwards compatibility; this
 * endpoint is new, and a GET would carry the token request in the query string, where access logs
 * and proxies record it.
 */
public class MtlsZoneAvailabilityFilter implements Filter {
    private static final String POST = "POST";

    private final MtlsFeaturePolicy policy;

    public MtlsZoneAvailabilityFilter(MtlsFeaturePolicy policy) {
        this.policy = policy;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest http = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        boolean token = RawPeerCertificateCaptureFilter.isMtlsTokenPath(http);
        // Header-based switching requires bearer authentication later in the chain. The names
        // controller enforces the policy again after that authorized switch, against the target zone.
        boolean names = MtlsTrustBundleEndpoints.PATH.equals(http.getServletPath())
                && http.getHeader(IdentityZoneSwitchingFilter.HEADER) == null
                && http.getHeader(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER) == null;
        if ((token || names) && !policy.isEnabled()) {
            httpResponse.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        if (token && !POST.equalsIgnoreCase(http.getMethod())) {
            httpResponse.setHeader("Allow", POST);
            httpResponse.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }
        chain.doFilter(request, response);
    }
}
