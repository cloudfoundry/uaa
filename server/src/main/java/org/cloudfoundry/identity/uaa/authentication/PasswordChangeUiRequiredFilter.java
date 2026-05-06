package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestCache;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class PasswordChangeUiRequiredFilter extends OncePerRequestFilter {

    private static final String MATCH_PATH = "/force_password_change";
    private static final String COMPLETED_PATH = "/force_password_change_completed";

    private final RequestMatcher matchPath;
    private final RequestMatcher completedPath;
    private final UaaSavedRequestCache cache;

    public PasswordChangeUiRequiredFilter() {
        this(new UaaSavedRequestCache());
        this.cache.setRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher("/oauth/authorize**"));
    }

    public PasswordChangeUiRequiredFilter(UaaSavedRequestCache cache) {
        this.cache = cache;
        this.matchPath = PathPatternRequestMatcher.withDefaults().matcher(MATCH_PATH);
        this.completedPath = PathPatternRequestMatcher.withDefaults().matcher(COMPLETED_PATH);
    }

    @Override
    protected void doFilterInternal(
            final @NonNull HttpServletRequest request,
            final @NonNull HttpServletResponse response,
            final @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (isCompleted(request)) {
            logger.debug("Forced password change has been completed.");
            SavedRequest savedRequest = cache.getRequest(request, response);
            if (savedRequest != null) {
                sendRedirect(savedRequest.getRedirectUrl(), request, response);
            } else {
                sendRedirect("/", request, response);
            }
        } else if (needsPasswordReset(request) && !matchPath.matches(request)) {
            logger.debug("Password change is required for user.");
            if (cache.getRequest(request, response) == null) {
                cache.saveRequest(request, response);
            }
            sendRedirect(MATCH_PATH, request, response);
        } else if (matchPath.matches(request) && isAuthenticated() && !needsPasswordReset(request)) {
            sendRedirect("/", request, response);
        } else {
            //pass through
            filterChain.doFilter(request, response);
        }
    }

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.isAuthenticated();
    }

    private boolean isCompleted(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof UaaAuthentication uaa) {
            return uaa.isAuthenticated() && !SessionUtils.isPasswordChangeRequired(request.getSession()) && completedPath.matches(request);
        }
        return false;
    }

    protected void sendRedirect(String redirectUrl, HttpServletRequest request, HttpServletResponse response) throws IOException {
        String location = (redirectUrl.startsWith("/") ? request.getContextPath() : "") + redirectUrl;
        logger.debug("Redirecting request to " + location);
        response.sendRedirect(location);
    }

    private boolean needsPasswordReset(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication instanceof UaaAuthentication &&
                SessionUtils.isPasswordChangeRequired(request.getSession()) &&
                authentication.isAuthenticated();
    }

}
