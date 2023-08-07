package org.cloudfoundry.identity.uaa;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import brave.CurrentSpanCustomizer;
import brave.SpanCustomizer;
import brave.Tracing;
import brave.context.slf4j.MDCScopeDecorator;
import brave.http.HttpTracing;
import brave.propagation.CurrentTraceContext;
import brave.propagation.CurrentTraceContext.ScopeDecorator;
import brave.propagation.ThreadLocalCurrentTraceContext;
import brave.servlet.TracingFilter;
import brave.spring.webmvc.SpanCustomizingAsyncHandlerInterceptor;

/** This adds tracing configuration to any web mvc controllers or rest template clients. */
@Configuration
// Importing a class is effectively the same as declaring bean methods
@Import(SpanCustomizingAsyncHandlerInterceptor.class)
public class TracingAutoConfiguration {

  /** Allows log patterns to use {@code %{traceId}} {@code %{spanId}} and {@code %{userName}} */
  @Bean ScopeDecorator correlationScopeDecorator() {
    return MDCScopeDecorator.newBuilder()
            .build();
  }

  /** Propagates trace context between threads. */
  @Bean CurrentTraceContext currentTraceContext(ScopeDecorator correlationScopeDecorator) {
    return ThreadLocalCurrentTraceContext.newBuilder()
            .addScopeDecorator(correlationScopeDecorator)
            .build();
  }

  /** Controls aspects of tracing such as the service name that shows up in the UI */
  @Bean Tracing tracing(
          @Value("${brave.localServiceName:${spring.application.name}}") String serviceName,
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

  /** Allows someone to add tags to a span if a trace is in progress. */
  @Bean SpanCustomizer spanCustomizer(Tracing tracing) {
    return CurrentSpanCustomizer.create(tracing);
  }

  /** Decides how to name and tag spans. By default they are named the same as the http method. */
  @Bean HttpTracing httpTracing(Tracing tracing) {
    return HttpTracing.create(tracing);
  }

  /** Creates server spans for HTTP requests */
  @Bean Filter tracingFilter(HttpTracing httpTracing) {
    return TracingFilter.create(httpTracing);
  }

  /** Adds MVC Controller tags to server spans */
  @Bean WebMvcConfigurer tracingWebMvcConfigurer(
          final SpanCustomizingAsyncHandlerInterceptor webMvcTracingCustomizer) {
    return new WebMvcConfigurerAdapter() {
      /** Adds application-defined web controller details to HTTP server spans */
      @Override public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(webMvcTracingCustomizer);
      }
    };
  }
}

