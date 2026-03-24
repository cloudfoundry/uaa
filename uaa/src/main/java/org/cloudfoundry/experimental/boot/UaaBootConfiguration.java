package org.cloudfoundry.experimental.boot;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableConfigurationProperties({UaaBootConfiguration.ServerHttp.class})
public class UaaBootConfiguration implements ServletContextInitializer, WebMvcConfigurer {

    @ConfigurationProperties(prefix = "server.http")
    record ServerHttp(
            @DefaultValue("-1") int port,
            @DefaultValue("12000") int keepAliveTimeout,
            @DefaultValue("20000") int connectionTimeout,
            @DefaultValue("14336") int maxHttpHeaderSize,
            @DefaultValue("127.0.0.1") String address,
            @DefaultValue("true") boolean bindOnInit
    ) {}

    @Bean
    WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> enableDefaultServlet() {
        return (factory) -> factory.setRegisterDefaultServlet(true);
    }

    /**
     * Overrides the order of the Spring Session filter (SessionRepositoryFilter).
     * Must run AFTER ZonePathContextRewritingFilter (order +1) and BEFORE
     * ZoneContextPathSessionFilter (order +51) so the zone session wrapper can delegate
     * to the Spring Session-backed session.
     * Order: rewriting(+1) → Spring Session(+2) → zone session(+51) → Spring Security
     */
    @Bean
    FilterRegistrationBean<Filter> sessionRepositoryFilterRegistration(
            @Qualifier("springSessionRepositoryFilter") Filter sessionRepositoryFilter) {
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>(sessionRepositoryFilter);
        bean.setDispatcherTypes(DispatcherType.REQUEST, DispatcherType.ERROR);
        bean.addUrlPatterns("/*");
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 2);
        return bean;
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {
        HttpSessionEventPublisher publisher = new HttpSessionEventPublisher();
        servletContext.addListener(publisher);
    }
}
