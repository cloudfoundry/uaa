package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import java.io.IOException;

/** Endpoint-level policies for {@code /oauth/mtls/token}. Not implemented yet: passes every request through. */
public class MtlsEndpointAvailabilityFilter implements Filter {

    public MtlsEndpointAvailabilityFilter(boolean mtlsEnabled) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        chain.doFilter(request, response);
    }
}
