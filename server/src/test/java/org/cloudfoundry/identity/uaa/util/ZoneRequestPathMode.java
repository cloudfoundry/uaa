package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Request path mode for tests: default path or zone path matching the request shape
 * <em>after</em> {@link org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter}.
 * <p>
 * Intention: for ZONE_PATH, the request is as if the filter has already run — context path
 * includes {@code /z/{subdomain}}, servlet path is only the path suffix (e.g. {@code /login}),
 * and request URI = context path + servlet path. Thymeleaf and redirect logic then see
 * {@code getContextPath()} and generate correct zone-prefixed URLs.
 * <p>
 * When building MockMvc request builders (get/post) for ZONE_PATH, use context path and
 * servlet path so the built request matches this shape, e.g.
 * {@code get(ctx + pathSuffix).contextPath(ctx).servletPath(pathSuffix)} with
 * {@code ctx = "/z/" + getSubdomain()}. Do not use only {@code get("/z/{subdomain}" + pathSuffix)}
 * without setting context path.
 */
public enum ZoneRequestPathMode {
    DEFAULT(""),
    ZONE_PATH("test-zone");

    private final String subdomain;

    ZoneRequestPathMode(String subdomain) {
        this.subdomain = subdomain;
    }

    public String getSubdomain() {
        return subdomain;
    }

    /** Path prefix for redirects/links: "" for DEFAULT, "/z/test-zone" for ZONE_PATH. */
    public String redirectPrefix() {
        return subdomain.isEmpty() ? "" : "/z/" + subdomain;
    }

    /** Sets IdentityZoneHolder so it matches this mode. ZONE_PATH uses a test zone; DEFAULT leaves current zone. */
    public void setZone() {
        if (this == ZONE_PATH) {
            IdentityZoneHolder.set(MultitenancyFixture.identityZone("test-zone-id", subdomain));
        }
    }

    /**
     * Applies the request path to the given request. For ZONE_PATH, sets the context path to include
     * {@code /z/{subdomain}} (appended to any existing context path) and the servlet path to the path
     * suffix only, matching the rewritten request after ZonePathContextRewritingFilter.
     * Idempotent: if the context path already ends with {@code /z/{subdomain}}, it is not appended again.
     */
    public void applyRequestPath(MockHttpServletRequest request, String pathSuffix) {
        if (subdomain.isEmpty()) {
            request.setRequestURI(pathSuffix);
            request.setServletPath(pathSuffix);
        } else {
            String zoneSuffix = "/z/" + subdomain;
            String baseContext = request.getContextPath() != null ? request.getContextPath() : "";
            String zoneContextPath = baseContext.endsWith(zoneSuffix) ? baseContext : baseContext + zoneSuffix;
            request.setContextPath(zoneContextPath);
            request.setServletPath(pathSuffix);
            request.setRequestURI(zoneContextPath + pathSuffix);
        }
    }
}
