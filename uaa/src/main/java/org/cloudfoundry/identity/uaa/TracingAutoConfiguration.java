package org.cloudfoundry.identity.uaa;

import brave.Tracing;
import brave.context.slf4j.MDCScopeDecorator;
import brave.http.HttpTracing;
import brave.jakarta.servlet.TracingFilter;
import brave.propagation.CurrentTraceContext;
import brave.propagation.CurrentTraceContext.ScopeDecorator;
import brave.propagation.ThreadLocalCurrentTraceContext;
import jakarta.servlet.Filter;
import org.cloudfoundry.identity.uaa.brave.SpanCustomizingAsyncHandlerInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * This adds tracing configuration to any web mvc controllers or rest template clients.
 */
@Configuration
// Importing a class is effectively the same as declaring bean methods
@Import(SpanCustomizingAsyncHandlerInterceptor.class)
public class TracingAutoConfiguration {

    /**
     * Allows log patterns to use {@code %{traceId}} {@code %{spanId}} and {@code %{userName}}
     */
    @Bean
    ScopeDecorator correlationScopeDecorator() {
        return MDCScopeDecorator.newBuilder()
                .build();
    }

    /**
     * Propagates trace context between threads.
     */
    @Bean
    CurrentTraceContext currentTraceContext(ScopeDecorator correlationScopeDecorator) {
        return ThreadLocalCurrentTraceContext.newBuilder()
                .addScopeDecorator(correlationScopeDecorator)
                .build();
    }

    /**
     * Controls aspects of tracing such as the service name that shows up in the UI
     */
    @Bean
    Tracing tracing(
            @Value("${brave.localServiceName:uaa}") String serviceName,
            @Value("${brave.supportsJoin:true}") boolean supportsJoin,
            @Value("${brave.traceId128Bit:false}") boolean traceId128Bit,
            CurrentTraceContext currentTraceContext) {
        return Tracing.newBuilder()
                .localServiceName(serviceName)
                .supportsJoin(supportsJoin)
                .traceId128Bit(traceId128Bit)
                .currentTraceContext(currentTraceContext)
                .build();
    }

    /**
     * Decides how to name and tag spans. By default they are named the same as the http method.
     */
    @Bean
    HttpTracing httpTracing(Tracing tracing) {
        return HttpTracing.create(tracing);
    }

    /**
     * Creates server spans for HTTP requests
     */
    @Bean
    FilterRegistrationBean<Filter> tracingFilter(HttpTracing httpTracing) {
        Filter filter = TracingFilter.create(httpTracing);
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }
}

