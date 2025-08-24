package org.cloudfoundry.identity.uaa.brave;

import brave.http.HttpTracing;
import brave.jakarta.servlet.TracingFilter;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.springframework.context.ApplicationContext;

import java.io.IOException;

import static org.springframework.web.context.support.WebApplicationContextUtils.getRequiredWebApplicationContext;

public final class DelegatingTracingFilter implements Filter {

    Filter delegate; // servlet ensures create is directly followed by init, so no need for volatile

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        Filter tracingFilter = delegate;
        if (tracingFilter == null) { // don't break on initialization error.
            chain.doFilter(request, response);
        } else {
            tracingFilter.doFilter(request, response, chain);
        }
    }

    @Override public void init(FilterConfig filterConfig) {
        ApplicationContext ctx = getRequiredWebApplicationContext(filterConfig.getServletContext());
        HttpTracing httpTracing = WebMvcRuntime.get().httpTracing(ctx);
        delegate = TracingFilter.create(httpTracing);
    }

    @Override public void destroy() {
        // TracingFilter is stateless, so nothing to destroy
    }
}
