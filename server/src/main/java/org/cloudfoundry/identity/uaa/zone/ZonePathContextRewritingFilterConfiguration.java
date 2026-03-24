package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.util.TimeService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
public class ZonePathContextRewritingFilterConfiguration {

    /**
     * Zone path rewriting runs as a servlet filter (enabled) so it executes before Spring Security
     * selects a filter chain. That way the request path is rewritten to context path + servlet path
     * (e.g. /z/myzone + /Codes) before security matchers run, so patterns like /Codes/** match correctly.
     */
    @Bean(ZonePathContextRewritingFilter.BEAN_NAME)
    FilterRegistrationBean<ZonePathContextRewritingFilter> zonePathContextRewritingFilter(
            @Value("${zones.paths.enabled:false}") boolean zonePathsEnabled) {
        ZonePathContextRewritingFilter filter = new ZonePathContextRewritingFilter(zonePathsEnabled);
        FilterRegistrationBean<ZonePathContextRewritingFilter> bean = new FilterRegistrationBean<>(filter);
        bean.addUrlPatterns("/*");
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 1); // before SessionRepositoryFilter (HIGHEST_PRECEDENCE + 50) and Spring Security
        return bean;
    }

    /**
     * Registers ZoneContextPathSessionFilter to run AFTER SessionRepositoryFilter (HIGHEST_PRECEDENCE + 50)
     * so that it wraps the Spring Session-backed request. This ensures request.getSession() first goes
     * through ZoneContextPathSessionFilter (returning a zone-scoped subsession view) which delegates
     * to SessionRepositoryFilter's session (the actual Spring Session-backed session).
     */
    @Bean(ZoneContextPathSessionFilter.BEAN_NAME)
    FilterRegistrationBean<ZoneContextPathSessionFilter> zoneContextPathSessionFilter(TimeService timeService) {
        ZoneContextPathSessionFilter filter = new ZoneContextPathSessionFilter(timeService);
        FilterRegistrationBean<ZoneContextPathSessionFilter> bean = new FilterRegistrationBean<>(filter);
        bean.addUrlPatterns("/*");
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 51); // after SessionRepositoryFilter (HIGHEST_PRECEDENCE + 50)
        return bean;
    }
}
