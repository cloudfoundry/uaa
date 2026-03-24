package org.cloudfoundry.identity.uaa.zone;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpSession;

import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter.DEFAULT_ZONE_SUBDOMAIN_PATH;

/**
 * Request wrapper that intercepts {@link #getSession(boolean)} and returns a
 * {@link ZonePathHttpSession} scoped to the current context path
 * (or "" if none). The container session holds attributes for each context path under prefixed keys
 * (see {@link ZonePathHttpSession}).
 * <p>
 * A single request always has exactly one context path, so at most one
 * {@link ZonePathHttpSession} is created per wrapper instance.
 */
public class ZoneContextPathSessionRequestWrapper extends HttpServletRequestWrapper {

    /**
     * Prefix for container session attribute names. Each context path has one attribute:
     * {@code ATTRIBUTE_NAME_PREFIX + contextPathKey} (with "" mapped to "default").
     */
    public static final String ATTRIBUTE_NAME_PREFIX =
            ZonePathHttpSession.class.getName() + ".";

    private final TimeService timeService;
    private ZonePathHttpSession cachedSession;

    public ZoneContextPathSessionRequestWrapper(HttpServletRequest request, TimeService timeService) {
        super(request);
        this.timeService = timeService;
    }

    private HttpServletRequest getDelegateRequest() {
        return (HttpServletRequest) getRequest();
    }

    /**
     * Returns a {@link ZonePathHttpSession} scoped to the current context path. At this point
     * the context path has already been rewritten by {@link ZonePathContextRewritingFilter} to
     * include the zone prefix (e.g. {@code /uaa/z/myzone}) when path-based zone access is used.
     */
    @Override
    public HttpSession getSession(boolean create) {
        if (cachedSession != null && !cachedSession.isInvalidated()) {
            return cachedSession;
        }
        cachedSession = null;

        HttpSession containerSession = getDelegateRequest().getSession(create);
        if (containerSession == null) {
            return null;
        }

        String contextPathKey = contextPathKey();
        String attributeName = attributeNameForContextPath(contextPathKey);

        cachedSession = new ZonePathHttpSession(containerSession, contextPathKey, attributeName, timeService);
        if (!cachedSession.isNew()) {
            cachedSession.touchLastAccessedTime();
        }
        return cachedSession;
    }

    /**
     * Attribute name on the container session for this context path. Empty context path uses "default".
     */
    public static String attributeNameForContextPath(String contextPathKey) {
        return ATTRIBUTE_NAME_PREFIX + (contextPathKey.isEmpty() ? DEFAULT_ZONE_SUBDOMAIN_PATH : contextPathKey);
    }

    @Override
    public HttpSession getSession() {
        return getSession(true);
    }

    /**
     * Delegates to the underlying request so the container session's ID is changed (e.g. for session
     * fixation prevention after login). If the container creates a new session object, our
     * context-path attributes are copied to the new session so sub-sessions still work.
     */
    @Override
    public String changeSessionId() {
        HttpServletRequest delegate = getDelegateRequest();
        HttpSession containerSessionBefore = delegate.getSession(false);
        Map<String, Object> ourAttributesSnapshot = null;
        if (containerSessionBefore != null) {
            ourAttributesSnapshot = snapshotOurAttributes(containerSessionBefore);
        }
        String newId = delegate.changeSessionId();
        if (containerSessionBefore != null && ourAttributesSnapshot != null && !ourAttributesSnapshot.isEmpty()) {
            HttpSession containerSessionAfter = delegate.getSession(false);
            if (containerSessionAfter != null && containerSessionAfter != containerSessionBefore) {
                restoreOurAttributes(containerSessionAfter, ourAttributesSnapshot);
            }
        }
        return newId;
    }

    private Map<String, Object> snapshotOurAttributes(HttpSession containerSession) {
        Map<String, Object> snapshot = new HashMap<>();
        Enumeration<String> names = containerSession.getAttributeNames();
        if (names == null) {
            names = Collections.emptyEnumeration();
        }
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            if (name.startsWith(ATTRIBUTE_NAME_PREFIX)) {
                snapshot.put(name, containerSession.getAttribute(name));
            }
        }
        return snapshot;
    }

    private void restoreOurAttributes(HttpSession containerSession, Map<String, Object> snapshot) {
        snapshot.forEach(containerSession::setAttribute);
    }

    /**
     * Returns the context path key used to store this session. For {@code /z/default} path-based requests,
     * the context path is e.g. {@code /uaa/z/default} but we use the original context path (e.g. {@code /uaa})
     * so that {@code /profile} and {@code /z/default/profile} share the same session/cookie.
     */
    private String contextPathKey() {
        String cp = getContextPath();
        if (cp != null && cp.endsWith("/z/" + DEFAULT_ZONE_SUBDOMAIN_PATH)) {
            Object orig = getAttribute(ZonePathContextRewritingFilter.ZONE_ORIGINAL_CONTEXT_PATH);
            if (orig instanceof String s && !s.isEmpty()) {
                return s;
            }
            return UaaStringUtils.EMPTY_STRING;
        }
        return (cp != null && !cp.isEmpty()) ? cp : UaaStringUtils.EMPTY_STRING;
    }
}
