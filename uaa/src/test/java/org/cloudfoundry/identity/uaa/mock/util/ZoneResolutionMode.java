package org.cloudfoundry.identity.uaa.mock.util;

import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.springframework.http.HttpMethod;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;

import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.hasText;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * Mode for resolving identity zone in MockMvc tests: by host subdomain or by path prefix {@code /z/{subdomain}/}.
 * ZONE_PATH simulates the effect of {@link org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter}:
 * the context path includes {@code /z/{subdomain}} and the request path (servlet path) is just the path suffix.
 */
public enum ZoneResolutionMode {
    SUBDOMAIN {
        @Override
        public MockHttpServletRequestBuilder createRequestBuilder(String subdomain, HttpMethod method, String contextPath, String pathSuffix) {
            if (StringUtils.hasText(subdomain)) {
                return requestBuilderForMethod(method, pathSuffix)
                        .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                        .contextPath(hasText(contextPath) ? contextPath : "");
            } else {
                return requestBuilderForMethod(method, pathSuffix)
                        .contextPath(hasText(contextPath) ? contextPath : "");
            }
        }

        @Override
        public String getServletPath(String subdomain, String pathSuffix) {
            return pathSuffix;
        }
    },
    /**
     * Zone resolved via path prefix. The context path is set to include {@code /z/{subdomain}} so that
     * the request appears as if {@link org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter}
     * has already rewritten it (context path includes zone, servlet path is the path suffix only).
     */
    ZONE_PATH {
        @Override
        public MockHttpServletRequestBuilder createRequestBuilder(String subdomain, HttpMethod method, String contextPath, String pathSuffix) {
            if (StringUtils.hasText(subdomain)) {
                String zonePrefixPath = "/z/" + subdomain;
                return requestBuilderForMethod(method, zonePrefixPath + pathSuffix)
                        .contextPath(hasText(contextPath) ? contextPath : "");
            } else {
                return requestBuilderForMethod(method, contextPath + pathSuffix)
                        .contextPath(hasText(contextPath) ? contextPath : "");
            }
        }

        @Override
        public String getServletPath(String subdomain, String pathSuffix) {
            return pathSuffix;
        }
    };

    public MockHttpServletRequestBuilder createRequestBuilder(String subdomain, HttpMethod method, String pathSuffix) {
        return createRequestBuilder(subdomain, method, "", pathSuffix);
    }

    public abstract MockHttpServletRequestBuilder createRequestBuilder(
            String subdomain,
            HttpMethod method,
            String contextPath,
            String pathSuffix
    );

    public abstract String getServletPath(String subdomain, String pathSuffix);

    public static MockHttpServletRequestBuilder requestBuilderForMethod(HttpMethod method, String path, Object... pathVars) {
        if (method == HttpMethod.GET) {
            return get(path, pathVars);
        }
        if (method == HttpMethod.POST) {
            return post(path, pathVars);
        }
        if (method == HttpMethod.PUT) {
            return put(path, pathVars);
        }
        if (method == HttpMethod.DELETE) {
            return delete(path, pathVars);
        }
        if (method == HttpMethod.OPTIONS) {
            return options(path, pathVars);
        }
        if (method == HttpMethod.PATCH) {
            return patch(path, pathVars);
        }
        throw new IllegalArgumentException("Unsupported method: " + method);
    }
}
