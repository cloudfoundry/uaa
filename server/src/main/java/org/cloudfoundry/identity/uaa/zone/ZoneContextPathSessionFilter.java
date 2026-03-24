package org.cloudfoundry.identity.uaa.zone;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;

/**
 * Wraps the request so that {@link HttpServletRequest#getSession()} returns a
 * context-path-scoped sub-session ({@link ZonePathHttpSession}) stored inside the
 * container session. Runs after {@link org.springframework.session.web.http.SessionRepositoryFilter}
 * (when Spring Session is active) so that the zone session wrapper delegates to the
 * Spring Session-backed session.
 *
 * <p>Zone session attributes are written directly to the container session (see
 * {@link ZonePathHttpSession}), so no flush step is needed.
 */
public class ZoneContextPathSessionFilter extends OncePerRequestFilter {

    public static final String BEAN_NAME = "zoneContextPathSessionFilter";

    public static final String JSESSIONID = "JSESSIONID";

    private final TimeService timeService;

    public ZoneContextPathSessionFilter(TimeService timeService) {
        this.timeService = timeService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        ZoneContextPathSessionRequestWrapper wrappedRequest = new ZoneContextPathSessionRequestWrapper(request, timeService);
        ZoneContextPathSessionResponseWrapper wrappedResponse = new ZoneContextPathSessionResponseWrapper(response);
        try {
            filterChain.doFilter(wrappedRequest, wrappedResponse);
        } finally {
            maybeClearJSessionIdIfNoSubSessions(request, wrappedResponse);
        }
    }

    private void maybeClearJSessionIdIfNoSubSessions(HttpServletRequest request,
                                                     ZoneContextPathSessionResponseWrapper response) {
        if (response.isCommitted()) {
            return;
        }
        HttpSession containerSession = request.getSession(false);
        if (containerSession == null) {
            return;
        }
        String prefix = ZoneContextPathSessionRequestWrapper.ATTRIBUTE_NAME_PREFIX;
        Enumeration<String> names = containerSession.getAttributeNames();
        if (names == null) {
            names = Collections.emptyEnumeration();
        }
        while (names.hasMoreElements()) {
            if (names.nextElement().startsWith(prefix)) {
                return; // at least one context-path sub-session still present
            }
        }
        String path = request.getContextPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        HttpServletResponse rawResponse = (HttpServletResponse) response.getResponse();
        rawResponse.addHeader("Set-Cookie", JSESSIONID + "=; Max-Age=0; Path=" + path);
    }
}
