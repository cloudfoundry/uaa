package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import java.io.IOException;

/** Zone-level availability of the mTLS endpoints. Not implemented yet: passes every request through. */
public class MtlsZoneAvailabilityFilter implements Filter {

    public MtlsZoneAvailabilityFilter(MtlsFeaturePolicy policy) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        chain.doFilter(request, response);
    }
}
