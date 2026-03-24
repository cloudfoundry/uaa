package org.cloudfoundry.identity.uaa.zone;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpSession;

import org.cloudfoundry.identity.uaa.util.TimeService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import static org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter.DEFAULT_ZONE_SUBDOMAIN_PATH;

/**
 * HttpSession view scoped to a context path. Each attribute is stored directly on the
 * container session under a prefixed key: {@code containerSessionAttributeName + ATTRIBUTE_KEY_DELIMITER + name}.
 * This ensures Spring Session's dirty-tracking sees every read/write immediately and
 * avoids timing issues (e.g. with MySQL JDBC session store). {@link #invalidate()}
 * removes all attributes for this context path from the container session; it does
 * not invalidate the container session itself.
 * <p>
 * Each subsession has a unique {@link #getId()} so that session repositories and
 * the application can distinguish subsessions: container session ID plus the context
 * path with '/' replaced by '-'.
 */
public class ZonePathHttpSession implements HttpSession {

    /**
     * Delimiter between the zone prefix and the attribute name on the container session.
     * Public so tests and other code can build container keys without hardcoding the delimiter.
     */
    public static final String ATTRIBUTE_KEY_DELIMITER = ".";

    /**
     * Key used for the root context path (empty or "/") in session ID suffixes.
     * Also reserved as a zone subdomain to prevent collisions.
     */
    private static final String DEFAULT_CONTEXT_PATH_KEY = DEFAULT_ZONE_SUBDOMAIN_PATH;

    static final String CREATION_TIME_KEY = "__creationTime__";
    static final String LAST_ACCESSED_TIME_KEY = "__lastAccessedTime__";

    private final HttpSession containerSession;
    private final TimeService timeService;
    private final String containerSessionAttributeName;
    /** Prefix for this zone's attributes on the container: containerSessionAttributeName + ATTRIBUTE_KEY_DELIMITER */
    private final String attributeKeyPrefix;
    /** Suffix for {@link #getId()}: context path with '/' replaced by '-', or {@link #DEFAULT_CONTEXT_PATH_KEY} for root. */
    private final String sessionIdSuffix;

    private final long creationTime;
    private long lastAccessedTime;
    private final boolean isNew;
    private boolean invalidated;

    public ZonePathHttpSession(HttpSession containerSession,
                               String contextPathKey,
                               String containerSessionAttributeName,
                               TimeService timeService) {
        this.containerSession = containerSession;
        this.timeService = timeService;
        this.containerSessionAttributeName = containerSessionAttributeName;
        this.attributeKeyPrefix = containerSessionAttributeName + ATTRIBUTE_KEY_DELIMITER;
        this.sessionIdSuffix = sessionIdSuffixFromContextPath(contextPathKey);

        String creationTimeContainerKey = containerKey(CREATION_TIME_KEY);
        Object storedCreationTime = containerSession.getAttribute(creationTimeContainerKey);
        if (storedCreationTime instanceof Long ct) {
            this.creationTime = ct;
            Object storedLastAccessed = containerSession.getAttribute(containerKey(LAST_ACCESSED_TIME_KEY));
            this.lastAccessedTime = (storedLastAccessed instanceof Long la) ? la : ct;
            this.isNew = false;
        } else {
            long now = timeService.getCurrentTimeMillis();
            this.creationTime = now;
            this.lastAccessedTime = now;
            this.isNew = true;
            containerSession.setAttribute(creationTimeContainerKey, now);
            containerSession.setAttribute(containerKey(LAST_ACCESSED_TIME_KEY), now);
        }
    }

    private static String sessionIdSuffixFromContextPath(String contextPathKey) {
        if (contextPathKey == null || contextPathKey.isEmpty()) {
            return DEFAULT_CONTEXT_PATH_KEY;
        }
        String suffix = contextPathKey.replaceAll("/", "-").replaceFirst("^-+", "");
        return suffix.isEmpty() ? DEFAULT_CONTEXT_PATH_KEY : suffix;
    }

    private String containerKey(String name) {
        return containerSessionAttributeName + ATTRIBUTE_KEY_DELIMITER + name;
    }

    @Override
    public Object getAttribute(String name) {
        return containerSession.getAttribute(containerKey(name));
    }

    @Override
    public void setAttribute(String name, Object value) {
        String key = containerKey(name);
        if (value != null) {
            containerSession.setAttribute(key, value);
        } else {
            containerSession.removeAttribute(key);
        }
    }

    void touchLastAccessedTime() {
        long now = timeService.getCurrentTimeMillis();
        this.lastAccessedTime = now;
        containerSession.setAttribute(containerKey(LAST_ACCESSED_TIME_KEY), now);
    }

    @Override
    public void removeAttribute(String name) {
        containerSession.removeAttribute(containerKey(name));
    }

    @Override
    public String getId() {
        return containerSession.getId() + "-" + sessionIdSuffix;
    }

    @Override
    public ServletContext getServletContext() {
        return containerSession.getServletContext();
    }

    @Override
    public long getCreationTime() {
        return creationTime;
    }

    @Override
    public long getLastAccessedTime() {
        return lastAccessedTime;
    }

    @Override
    public void setMaxInactiveInterval(int interval) {
        containerSession.setMaxInactiveInterval(interval);
    }

    @Override
    public int getMaxInactiveInterval() {
        return containerSession.getMaxInactiveInterval();
    }

    @Override
    public boolean isNew() {
        return isNew;
    }

    public boolean isInvalidated() {
        return invalidated;
    }

    @Override
    public void invalidate() {
        invalidated = true;
        List<String> toRemove = new ArrayList<>();
        Enumeration<String> names = containerSession.getAttributeNames();
        if (names != null) {
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                if (name.startsWith(attributeKeyPrefix)) {
                    toRemove.add(name);
                }
            }
        }
        for (String name : toRemove) {
            try {
                containerSession.removeAttribute(name);
            } catch (IllegalStateException ignored) {
                // Container session was invalidated
            }
        }
    }

    @Override
    public Enumeration<String> getAttributeNames() {
        List<String> result = new LinkedList<>();
        Enumeration<String> names = containerSession.getAttributeNames();
        if (names != null) {
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                if (name.startsWith(attributeKeyPrefix)) {
                    String unprefixed = name.substring(attributeKeyPrefix.length());
                    if (!isReservedKey(unprefixed)) {
                        result.add(unprefixed);
                    }
                }
            }
        }
        return Collections.enumeration(result);
    }

    private static boolean isReservedKey(String key) {
        return CREATION_TIME_KEY.equals(key) || LAST_ACCESSED_TIME_KEY.equals(key);
    }
}
