package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestCache;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class PasswordChangeUiRequiredFilter extends OncePerRequestFilter {

    private final static String MATCH_PATH = "/force_password_change";
    private final static String IGNORE_PATH = "/login/mfa/**";
    private final static String COMPLETED_PATH = "/force_password_change_completed";

    private final AntPathRequestMatcher matchPath;
    private final AntPathRequestMatcher ignorePath;
    private final AntPathRequestMatcher completedPath;
    private final UaaSavedRequestCache cache;

    public PasswordChangeUiRequiredFilter(final UaaSavedRequestCache cache) {
        this.cache = cache;
        this.matchPath = new AntPathRequestMatcher(MATCH_PATH);
        this.ignorePath = new AntPathRequestMatcher(IGNORE_PATH);
        this.completedPath = new AntPathRequestMatcher(COMPLETED_PATH);
    }

    @Override
    protected void doFilterInternal(
            final @NonNull HttpServletRequest request,
            final @NonNull HttpServletResponse response,
            final @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (isIgnored(request)) {
            //pass through even though 'change' is required request
            filterChain.doFilter(request, response);
        } else if (isCompleted(request)) {
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

    protected boolean isIgnored(HttpServletRequest request) {
        return ignorePath.matches(request);
    }

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.isAuthenticated();
    }

    private boolean isCompleted(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof UaaAuthentication) {
            UaaAuthentication uaa = (UaaAuthentication) authentication;
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
