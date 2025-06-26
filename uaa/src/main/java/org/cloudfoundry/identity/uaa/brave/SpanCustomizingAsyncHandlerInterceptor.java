package org.cloudfoundry.identity.uaa.brave;

import brave.SpanCustomizer;
import brave.internal.Nullable;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.HandlerInterceptor;

public final class SpanCustomizingAsyncHandlerInterceptor implements HandlerInterceptor {
    static final String BEST_MATCHING_PATTERN_ATTRIBUTE =
            "org.springframework.web.servlet.HandlerMapping.bestMatchingPattern";

    @Autowired(required = false)
    HandlerParser handlerParser = new HandlerParser();

    SpanCustomizingAsyncHandlerInterceptor() { // hide the ctor so we can change later if needed
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object o) {
        Object span = request.getAttribute(SpanCustomizer.class.getName());
        if (span instanceof SpanCustomizer customizer) handlerParser.preHandle(request, o, customizer);
        return true;
    }

    @Override
    public void afterCompletion(
            HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        Object span = request.getAttribute(SpanCustomizer.class.getName());
        if (span instanceof SpanCustomizer) {
            setErrorAttribute(request, ex);
            setHttpRouteAttribute(request);
        }
    }

    static void setErrorAttribute(HttpServletRequest request, @Nullable Exception ex) {
        if (ex != null && request.getAttribute("error") == null) {
            request.setAttribute("error", ex);
        }
    }

    static void setHttpRouteAttribute(HttpServletRequest request) {
        Object httpRoute = request.getAttribute(BEST_MATCHING_PATTERN_ATTRIBUTE);
        request.setAttribute("http.route", httpRoute != null ? httpRoute.toString() : "");
    }
}
