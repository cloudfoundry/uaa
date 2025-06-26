/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.security.web;

import jakarta.servlet.RequestDispatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jmx.export.annotation.ManagedAttribute;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.util.Assert;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Post processor which injects an additional filter at the head
 * of each security filter chain.
 * <p/>
 * If the requireHttps property is set, and a non HTTP request is received (as
 * determined by the absence of the <tt>httpsHeader</tt>) the filter will either
 * redirect with a 301 or send an error code to the client.
 * Filter chains for which a redirect is required should be added to the
 * <tt>redirectToHttps</tt> list (typically
 * those serving browser clients). Clients in this list will also receive an
 * HSTS response header, as defined in
 * http://tools.ietf.org/html/draft-ietf-websec-strict-transport-sec-14.
 * <p/>
 * HTTP requests from any other clients will receive a JSON error message.
 * <p/>
 * The filter also wraps calls to the <tt>getRemoteAddr</tt> to give a more
 * accurate value for the remote client IP,
 * making use of the <tt>clientAddrHeader</tt> if available in the request.
 *
 * @author Luke Taylor
 */
@ManagedResource(
        objectName = "cloudfoundry.identity:name=FilterChainProcessor",
        description = "Ability to dump requests through JMX"
)
public class SecurityFilterChainPostProcessor implements BeanPostProcessor {
    public static class ReasonPhrase {
        private int code;
        private String phrase;

        public ReasonPhrase(int code, String phrase) {
            this.code = code;
            this.phrase = phrase;
        }

        public int getCode() {
            return code;
        }

        public String getPhrase() {
            return phrase;
        }
    }

    private final Logger logger = LoggerFactory.getLogger(getClass());
    private boolean requireHttps;
    private List<String> redirectToHttps = Collections.emptyList();
    private List<String> ignore = Collections.emptyList();
    private boolean dumpRequests;
    private int httpsPort;

    private Map<Class<? extends Exception>, ReasonPhrase> errorMap = new HashMap<>();
    private Map<FilterPosition, Filter> additionalFilters;

    public void setErrorMap(Map<Class<? extends Exception>, ReasonPhrase> errorMap) {
        this.errorMap = errorMap;
    }

    public Map<Class<? extends Exception>, ReasonPhrase> getErrorMap() {
        return errorMap;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof SecurityFilterChain fc && !ignore.contains(beanName)) {
            logger.info("Processing security filter chain {}", beanName);

            if (additionalFilters != null) {
                for (Entry<FilterPosition, Filter> entry : additionalFilters.entrySet()) {
                    int position = entry.getKey().getPosition(fc);
                    if (position > fc.getFilters().size()) {
                        fc.getFilters().add(entry.getValue());
                    } else {
                        fc.getFilters().add(position, entry.getValue());
                    }
                }
            }

            Filter uaaFilter = new HttpsEnforcementFilter(beanName, redirectToHttps.contains(beanName));
            fc.getFilters().addFirst(uaaFilter);
        }

        return bean;
    }

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    /**
     * If set to true, HTTPS will be required for all requests.
     */
    public void setRequireHttps(boolean requireHttps) {
        this.requireHttps = requireHttps;
    }

    public boolean isRequireHttps() {
        return requireHttps;
    }

    public void setHttpsPort(int httpsPort) {
        this.httpsPort = httpsPort;
    }

    /**
     * Debugging feature. If enabled, and debug logging is enabled
     */
    @ManagedAttribute(description = "Enable dumping of incoming requests to the debug log")
    public void setDumpRequests(boolean dumpRequests) {
        this.dumpRequests = dumpRequests;
    }

    public void setRedirectToHttps(List<String> redirectToHttps) {
        Assert.notNull(redirectToHttps, "must not be null");
        this.redirectToHttps = redirectToHttps;
    }

    /**
     * List of filter chains which should be ignored completely.
     */
    public void setIgnore(List<String> ignore) {
        Assert.notNull(ignore, "must not be null");
        this.ignore = ignore;
    }

    /**
     * Additional filters to add to the chain after either HttpsEnforcementFilter or UaaLoggingFilter
     * has been added to the head of the chain. Filters will be inserted in Map iteration order,
     * at the position given by the entry key (or the end of the chain if the key &gt; size).
     * @param additionalFilters
     */
    public void setAdditionalFilters(Map<FilterPosition, Filter> additionalFilters) {
        this.additionalFilters = additionalFilters;
    }

    final class HttpsEnforcementFilter extends UaaLoggingFilter {
        private final boolean redirect;

        HttpsEnforcementFilter(String name, boolean redirect) {
            super(name);
            this.redirect = redirect;
        }

        @Override
        public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
                ServletException {
            HttpServletRequest request = (HttpServletRequest) req;
            HttpServletResponse response = (HttpServletResponse) res;

            if (request.isSecure() || (!requireHttps)) {
                // Ok. Just pass on.
                if (redirect) {
                    // Set HSTS header for browser clients
                    response.setHeader("Strict-Transport-Security", "max-age=31536000");
                }
                super.doFilter(req, response, chain);
                return;
            }

            logger.debug("Bad (non-https) request received from: {}", request.getRemoteHost());

            if (dumpRequests) {
                logger.debug(dumpRequest(request));
            }

            if (redirect) {
                RedirectUrlBuilder rb = new RedirectUrlBuilder();
                rb.setScheme("https");
                rb.setPort(httpsPort);
                rb.setContextPath(request.getContextPath());
                rb.setServletPath(request.getServletPath());
                rb.setPathInfo(request.getPathInfo());
                rb.setQuery(request.getQueryString());
                rb.setServerName(request.getServerName());
                // Send a 301 as suggested by
                // http://tools.ietf.org/html/draft-ietf-websec-strict-transport-sec-14#section-7.2
                String url = rb.getUrl();
                if (logger.isDebugEnabled()) {
                    logger.debug("Redirecting to {}", url);
                }
                response.setHeader("Location", url);
                response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
            } else {
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "{\"error\": \"request must be over https\"}");
            }
        }
    }

    class UaaLoggingFilter implements Filter {
        final Logger logger = LoggerFactory.getLogger(getClass());
        protected final String name;

        UaaLoggingFilter(String name) {
            this.name = name;
        }

        @Override
        public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
                ServletException {
            HttpServletRequest request = (HttpServletRequest) req;
            HttpServletResponse response = (HttpServletResponse) res;

            if (logger.isDebugEnabled()) {
                logger.debug("Filter chain '{}' processing request {} {}", name, request.getMethod(), request.getRequestURI());

                if (dumpRequests) {
                    logger.debug(dumpRequest(request));
                }
            }
            try {
                chain.doFilter(request, response);
            } catch (Exception x) {
                logger.error("Uncaught Exception:", x);
                if (req.getAttribute(RequestDispatcher.ERROR_EXCEPTION) == null) {
                    req.setAttribute(RequestDispatcher.ERROR_EXCEPTION, x);
                }
                if (x instanceof RequestRejectedException) {
                    request.setAttribute(RequestDispatcher.ERROR_REQUEST_URI, request.getRequestURI());
                    request.getRequestDispatcher("/rejected").forward(request, response);
                    return;
                }
                ReasonPhrase reasonPhrase = getErrorMap().get(x.getClass());
                if (null == reasonPhrase) {
                    for (Class<? extends Exception> clazz : getErrorMap().keySet()) {
                        if (clazz.isAssignableFrom(x.getClass())) {
                            reasonPhrase = getErrorMap().get(clazz);
                            break;
                        }
                    }
                    if (null == reasonPhrase) {
                        reasonPhrase = new ReasonPhrase(HttpStatus.INTERNAL_SERVER_ERROR.value(), HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
                    }
                }
                response.sendError(reasonPhrase.getCode(), reasonPhrase.getPhrase());
            }
        }

        @SuppressWarnings("unchecked")
        protected final String dumpRequest(HttpServletRequest r) {
            StringBuilder builder = new StringBuilder(256);
            builder.append("\n    ").append(r.getMethod()).append(" ").append(r.getRequestURI()).append("\n");
            Enumeration<String> e = r.getHeaderNames();

            while (e.hasMoreElements()) {
                String hdrName = e.nextElement();
                Enumeration<String> values = r.getHeaders(hdrName);

                while (values.hasMoreElements()) {
                    builder.append("    ").append(hdrName).append(": ").append(values.nextElement()).append("\n");
                }
            }
            return builder.toString();
        }

        @Override
        public void init(FilterConfig filterConfig) {
        }

        @Override
        public void destroy() {
        }
    }

    public static class FilterPosition {
        enum PLACEMENT {
            POSITION,
            BEFORE,
            AFTER
        }
        private int position = Integer.MAX_VALUE;
        private PLACEMENT placement = PLACEMENT.POSITION;
        private Class<?> clazz;

        public void setPosition(int position) {
            this.position = position;
            this.placement = PLACEMENT.POSITION;
        }

        public void setBefore(Class<?> clazz) {
            this.clazz = clazz;
            this.placement = PLACEMENT.BEFORE;
        }

        public void setAfter(Class<?> clazz) {
            this.clazz = clazz;
            this.placement = PLACEMENT.AFTER;
        }

        public int getPosition(SecurityFilterChain chain) {
            int index = chain.getFilters().size();
            if (clazz != null) {
                int pos = 0;
                for (Filter f : chain.getFilters()) {
                    if (clazz.equals(f.getClass())) {
                        index = pos;
                        break;
                    } else {
                        pos++;
                    }
                }
            }
            switch (placement) {
                case POSITION: return position;
                case BEFORE: return index;
                case AFTER: return Math.min(chain.getFilters().size(), index + 1);
            }
            return index;
        }

        public static FilterPosition position(int pos) {
            FilterPosition filterPosition = new FilterPosition();
            filterPosition.setPosition(pos);
            return filterPosition;
        }

        public static FilterPosition after(Class<?> clazz) {
            FilterPosition filterPosition = new FilterPosition();
            filterPosition.setAfter(clazz);
            return filterPosition;
        }

        public static FilterPosition before(Class<?> clazz) {
            FilterPosition filterPosition = new FilterPosition();
            filterPosition.setBefore(clazz);
            return filterPosition;
        }
    }
}
