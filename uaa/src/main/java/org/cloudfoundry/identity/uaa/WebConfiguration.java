package org.cloudfoundry.identity.uaa;

import org.apache.catalina.filters.HttpHeaderSecurityFilter;
import org.cloudfoundry.identity.uaa.web.BackwardsCompatibleScopeParsingFilter;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.servlet.DispatcherServlet;

import javax.servlet.Servlet;

@Configuration
public class WebConfiguration {

    @Bean
    public DispatcherServlet spring() {
        return new DispatcherServlet();
    }

    @Bean
    public ServletRegistrationBean servletRegistrationBean(
            @Qualifier("spring") DispatcherServlet servlet
    ) {
        ServletRegistrationBean<DispatcherServlet> servletRegistrationBean = new ServletRegistrationBean<>();
        servletRegistrationBean.setLoadOnStartup(1);
        servletRegistrationBean.setName("spring");
        servletRegistrationBean.addUrlMappings("/");
        MDC.put("context", "/"); // used to fill in %X{context} in our `property.log_pattern` log format

        servletRegistrationBean.setServlet(servlet);
        return servletRegistrationBean;
    }

    @Bean
    static DisableFiltersInBoot disableFilterInBoot() {
        return new DisableFiltersInBoot();
    }

    @Bean
    static FilterRegistrationBean<BackwardsCompatibleScopeParsingFilter> backwardsCompatibleScopeParsingFilterFilterRegistrationBean() {
        final FilterRegistrationBean<BackwardsCompatibleScopeParsingFilter> registration
                = new FilterRegistrationBean<>(new BackwardsCompatibleScopeParsingFilter());
        registration.addUrlPatterns("/*");
        return registration;
    }

    @Bean
    static FilterRegistrationBean<HttpHeaderSecurityFilter> httpHeaderSecurityFilterFilterRegistrationBean() {
        FilterRegistrationBean<HttpHeaderSecurityFilter> registration
                = new FilterRegistrationBean<>(new HttpHeaderSecurityFilter());
        registration.addInitParameter("hstsEnabled", "false");
        registration.addInitParameter("antiClickJackingEnabled", "false");
        registration.addInitParameter("blockContentTypeSniffingEnabled", "true");
        registration.addInitParameter("xssProtectionEnabled", "false");
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
