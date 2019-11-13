package org.cloudfoundry.identity.uaa;

import org.apache.catalina.filters.HttpHeaderSecurityFilter;
import org.cloudfoundry.identity.uaa.web.BackwardsCompatibleScopeParsingFilter;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.servlet.DispatcherServlet;

@Configuration
public class WebConfiguration {

    @Bean
    public ServletRegistrationBean servletRegistrationBean(
            final @Value("${server.servlet.context-path:/uaa}") String contextPath
    ) {
        final var servletRegistrationBean = new ServletRegistrationBean<>(new DispatcherServlet());
        servletRegistrationBean.setLoadOnStartup(1);
        servletRegistrationBean.setName("spring");
        servletRegistrationBean.addUrlMappings(contextPath);
        return servletRegistrationBean;
    }

    @Bean
    public ConfigurableServletWebServerFactory servletContainer(
            final @Value("${server.servlet.context-path:/uaa}") String contextPath
    ) {
        TomcatServletWebServerFactory tomcatContainerFactory = new TomcatServletWebServerFactory();

        MDC.put("context", contextPath);
        System.out.println(String.format("Starting UAA on context path [%s]", contextPath));
        // used to fill in %X{context} in our `property.log_pattern` log format
        // but this only works for the current thread... which is probably not going to handle HTTP requests

        tomcatContainerFactory.setContextPath(contextPath);
        return tomcatContainerFactory;
    }

    @Bean
    static DisableFiltersInBoot disableFilterInBoot() {
        return new DisableFiltersInBoot();
    }

    @Bean
    static FilterRegistrationBean<BackwardsCompatibleScopeParsingFilter> backwardsCompatibleScopeParsingFilterFilterRegistrationBean() {
        final var registration = new FilterRegistrationBean<>(new BackwardsCompatibleScopeParsingFilter());
        registration.addUrlPatterns("/*");
        return registration;
    }

    @Bean
    static FilterRegistrationBean<HttpHeaderSecurityFilter> httpHeaderSecurityFilterFilterRegistrationBean() {
        final var httpHeaderSecurityFilter = new HttpHeaderSecurityFilter();
        httpHeaderSecurityFilter.setHstsEnabled(false);
        httpHeaderSecurityFilter.setAntiClickJackingEnabled(false);
        httpHeaderSecurityFilter.setBlockContentTypeSniffingEnabled(true);
        httpHeaderSecurityFilter.setXssProtectionEnabled(false);
        final var registration = new FilterRegistrationBean<>(httpHeaderSecurityFilter);
        registration.addUrlPatterns("/*");
        return registration;
    }

    @Bean
    public ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisherServletListenerRegistrationBean() {
        return new ServletListenerRegistrationBean<>(new HttpSessionEventPublisher());
    }

//    @Configuration
//    public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
//
//        @Override
//        protected void configure(HttpSecurity httpSecurity) throws Exception {
//            httpSecurity.authorizeRequests().antMatchers("/**").permitAll();
//        }
//
//    }

//
//    @Bean
//    public DelegatingFilterProxy springSecurityFilterChain() {
//        DelegatingFilterProxy springSecurityFilterChain = new DelegatingFilterProxy();
//        springSecurityFilterChain.setContextAttribute("org.springframework.web.servlet.FrameworkServlet.CONTEXT.spring");
//        return springSecurityFilterChain;
//    }
//
//    @Bean
//    public FilterRegistrationBean<DelegatingFilterProxy> springSecurityFilterRegistration(
//            @Qualifier("springSecurityFilterChain") DelegatingFilterProxy delegatingFilterProxy
//    ) {
//        FilterRegistrationBean<DelegatingFilterProxy> registrationBean = new FilterRegistrationBean<>();
//        registrationBean.setFilter(delegatingFilterProxy);
//        registrationBean.addUrlPatterns("/*");
//        registrationBean.setDispatcherTypes(DispatcherType.REQUEST, DispatcherType.ERROR);
//        return registrationBean;
//    }
//
//    @Bean
//    public RequestContextFilter springRequestContextFilter() {
//        return new RequestContextFilter();
//    }
//
//    @Bean
//    public FilterRegistrationBean<RequestContextFilter> springSecurityFilterRegistration(
//            @Qualifier("springRequestContextFilter") RequestContextFilter springRequestContextFilter
//    ) {
//        FilterRegistrationBean<RequestContextFilter> registrationBean = new FilterRegistrationBean<>();
//        registrationBean.setFilter(springRequestContextFilter);
//        registrationBean.addUrlPatterns("/*");
//        return registrationBean;
//    }

}
