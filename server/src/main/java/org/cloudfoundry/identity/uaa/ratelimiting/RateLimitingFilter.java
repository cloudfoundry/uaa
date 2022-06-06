package org.cloudfoundry.identity.uaa.ratelimiting;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cloudfoundry.identity.uaa.ratelimiting.core.Limiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.RateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RateLimitingFilter extends HttpFilter {
    private static final Logger log = LoggerFactory.getLogger( RateLimitingFilter.class );

    // Not really unused, called by container to create Filter
    @SuppressWarnings("unused")
    public RateLimitingFilter() // default and production constructor
            throws ServletException {
        this( RateLimiter.isEnabled() ? new RateLimiterImpl() : null );
    }

    private final RateLimiter rateLimiter; // Null == disabled

    RateLimitingFilter( RateLimiter rateLimiter ) // flexible (real-actual and testing) constructor
            throws ServletException {
        this.rateLimiter = rateLimiter;
        init( new FilterConfig() {
            @Override
            public String getFilterName() {
                return RateLimitingFilter.class.getName();
            }

            @Override
            public ServletContext getServletContext() {
                return null;
            }

            @Override
            public String getInitParameter( String name ) {
                return null;
            }

            @Override
            public Enumeration<String> getInitParameterNames() {
                return Collections.emptyEnumeration();
            }
        } );
    }

    @Override
    protected void doFilter( HttpServletRequest request,
                             HttpServletResponse response, FilterChain filterChain )
            throws ServletException, IOException {
        if ( rateLimiter != null ) { // rateLimiting is active
            String requestPath = request.getRequestURI();
            try {
                Limiter limiter = rateLimiter.checkRequest( request );
                if ( log.isInfoEnabled() ) {
                    limiter.log( requestPath, log::info );
                }
                if ( limiter.shouldLimit() ) {
                    limitRequest( response );
                    return;
                }
            }
            catch ( RuntimeException e ) {
                log.error( "Unexpected RateLimiter error w/ path '" + requestPath + "'", e );
            }
        }
        filterChain.doFilter( request, response ); // just forward it!
    }

    private void limitRequest( HttpServletResponse response )
            throws IOException {
        response.sendError( 429, "Too Many Requests" );
    }
}
