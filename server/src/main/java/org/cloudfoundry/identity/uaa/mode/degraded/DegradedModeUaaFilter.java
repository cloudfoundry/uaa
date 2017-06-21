package org.cloudfoundry.identity.uaa.mode.degraded;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;


public class DegradedModeUaaFilter extends OncePerRequestFilter {

    private static Log logger = LogFactory.getLog(DegradedModeUaaFilter.class);


    private Set<String> permittedEndpoints;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String contextPath = request.getContextPath();
        logger.warn("Context Path:::"+contextPath);
        String uri = request.getRequestURI();
        logger.warn("Request URI:::"+uri);
        String requestPath = uri.substring(contextPath.length());
        logger.warn("Request URI substring:::"+uri.substring(contextPath.length()));

        if(this.permittedEndpoints.contains(requestPath) ||
                request.getMethod().equalsIgnoreCase(HttpMethod.GET.name()) ||
                request.getMethod().equalsIgnoreCase(HttpMethod.HEAD.name()) ||
                requestPath.startsWith("/saml")) {
            filterChain.doFilter(request, response);
        }else {
            String responseToClient = "{\"error\": \"UAA is currently in degraded mode - please try again later. " +
                    "Operations permitted in degraded mode are: getting a token(/oauth/token), checking a token(check_token)" +
                    ", Read SCIM and other UAA resources. \"}";
            logger.warn("Operation Not permitted in degraded mode::"+uri.substring(contextPath.length()));
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.addHeader("Content-Type", "application/json");
            response.getWriter().write(responseToClient);
            response.getWriter().flush();
            response.getWriter().close();
        }
    }

    public void setPermittedEndpoints(Set<String> permittedEndpoints) {
        this.permittedEndpoints = permittedEndpoints;
    }
}
