package org.cloudfoundry.identity.uaa.authentication;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class PasswordChangeUiRequiredFilter extends OncePerRequestFilter {

    private final String redirectUri;
    private final AntPathRequestMatcher matcher;
    private final List<AntPathRequestMatcher> ignorePaths;
    private final AntPathRequestMatcher completed = new AntPathRequestMatcher("/force_password_change_completed");
    private final RequestCache cache;

    public PasswordChangeUiRequiredFilter(String redirectUri, RequestCache cache, String... ignoreUris) {
        this.redirectUri = redirectUri;
        matcher = new AntPathRequestMatcher(redirectUri);
        this.cache = cache;
        ignorePaths = new LinkedList<>();
        if (ignoreUris!=null) {
            for (String s : ignoreUris) {
                ignorePaths.add(new AntPathRequestMatcher(s));
            }
        }
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (isIgnored(request, response)) {
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
        } else if (needsPasswordReset() && !matcher.matches(request)) {
            logger.debug("Password change is required for user.");
            cache.saveRequest(request, response);
            sendRedirect(redirectUri, request, response);
        } else if (matcher.matches(request) && isAuthenticated() && !needsPasswordReset()) {
            sendRedirect("/", request, response);
        } else {
            //pass through
            filterChain.doFilter(request, response);
        }
    }

    protected boolean isIgnored(HttpServletRequest request, HttpServletResponse response) {
        for (AntPathRequestMatcher matcher : ignorePaths) {
            if (matcher.matches(request)) {
                return true;
            }
        }
        return false;
    }

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.isAuthenticated();
    }

    protected boolean isCompleted(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication instanceof UaaAuthentication) {
            UaaAuthentication uaa = (UaaAuthentication)authentication;
            if (uaa.isAuthenticated() && !uaa.isRequiresPasswordChange() && completed.matches(request)) {
                return true;
            }
        }
        return false;
    }

    protected void sendRedirect(String redirectUrl, HttpServletRequest request, HttpServletResponse response) throws IOException {
        StringBuilder url = new StringBuilder(
            redirectUrl.startsWith("/") ? request.getContextPath() : ""
        );
        url.append(redirectUrl);
        String location = url.toString();
        logger.debug("Redirecting request to " + location);
        response.sendRedirect(location);
    }

    protected boolean needsPasswordReset() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null &&
            authentication instanceof UaaAuthentication &&
            ((UaaAuthentication)authentication).isRequiresPasswordChange() &&
            authentication.isAuthenticated();
    }
}
