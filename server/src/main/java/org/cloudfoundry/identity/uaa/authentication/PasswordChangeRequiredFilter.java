package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

public class PasswordChangeRequiredFilter extends OncePerRequestFilter {

    private final AuthenticationEntryPoint entryPoint;

    public PasswordChangeRequiredFilter(AuthenticationEntryPoint entryPoint) {
        this.entryPoint = entryPoint;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (needsPasswordReset(request.getSession())) {
            entryPoint.commence(request,
                                response,
                                new PasswordChangeRequiredException(
                                    (UaaAuthentication) getContext().getAuthentication(),
                                    "password reset is required"
                                )
            );
        } else {
            //pass through
            filterChain.doFilter(request, response);
        }
    }

    protected boolean needsPasswordReset(HttpSession session) {
        Authentication authentication = getContext().getAuthentication();
        return authentication != null &&
                authentication instanceof UaaAuthentication &&
                SessionUtils.isPasswordChangeRequired(session) &&
                authentication.isAuthenticated();
    }
}
