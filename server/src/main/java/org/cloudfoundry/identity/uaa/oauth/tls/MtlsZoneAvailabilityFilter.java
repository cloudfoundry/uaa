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

/** Runs after zone resolution, before client authentication. */
public class MtlsZoneAvailabilityFilter implements Filter {
    private final MtlsFeaturePolicy policy;

    public MtlsZoneAvailabilityFilter(MtlsFeaturePolicy policy) {
        this.policy = policy;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest http = (HttpServletRequest) request;
        boolean token = RawPeerCertificateCaptureFilter.isMtlsTokenPath(http);
        // Header-based switching requires bearer authentication later in the chain. The names
        // controller enforces the policy again after that authorized switch, against the target zone.
        boolean names = MtlsTrustBundleEndpoints.PATH.equals(http.getServletPath())
                && http.getHeader(IdentityZoneSwitchingFilter.HEADER) == null
                && http.getHeader(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER) == null;
        if ((token || names) && !policy.isEnabled()) {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        chain.doFilter(request, response);
    }
}
