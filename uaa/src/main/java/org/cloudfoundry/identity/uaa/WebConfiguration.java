package org.cloudfoundry.identity.uaa;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.RequestContextFilter;
import org.springframework.web.servlet.DispatcherServlet;

import javax.servlet.DispatcherType;
import javax.servlet.Servlet;

@Configuration
public class WebConfiguration {

    @Bean
    public Servlet spring() {
        DispatcherServlet servlet = new DispatcherServlet();
        
        servlet.setContextInitializerClasses("org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer");
        servlet.setContextConfigLocation("classpath*:spring-servlet.xml");
        return servlet;
    }

    @Bean
    public ServletRegistrationBean servletRegistrationBean(
            @Qualifier("spring") Servlet servlet
    ) {
        ServletRegistrationBean servletRegistrationBean = new ServletRegistrationBean();
        servletRegistrationBean.setName("spring");
        servletRegistrationBean.addUrlMappings("/");

        servletRegistrationBean.setServlet(servlet);
        return servletRegistrationBean;
    }

    @Bean
    public DelegatingFilterProxy springSecurityFilterChain() {
        DelegatingFilterProxy springSecurityFilterChain = new DelegatingFilterProxy();
        springSecurityFilterChain.setContextAttribute("org.springframework.web.servlet.FrameworkServlet.CONTEXT.spring");
        return springSecurityFilterChain;
    }

    @Bean
    public FilterRegistrationBean<DelegatingFilterProxy> springSecurityFilterRegistration(
            @Qualifier("springSecurityFilterChain") DelegatingFilterProxy delegatingFilterProxy
    ) {
        FilterRegistrationBean<DelegatingFilterProxy> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(delegatingFilterProxy);
        registrationBean.addUrlPatterns("/*");
        registrationBean.setDispatcherTypes(DispatcherType.REQUEST, DispatcherType.ERROR);
        return registrationBean;
    }

    @Bean
    public RequestContextFilter springRequestContextFilter() {
        return new RequestContextFilter();
    }

    @Bean
    public FilterRegistrationBean<RequestContextFilter> springSecurityFilterRegistration(
            @Qualifier("springRequestContextFilter") RequestContextFilter springRequestContextFilter
    ) {
        FilterRegistrationBean<RequestContextFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(springRequestContextFilter);
        registrationBean.addUrlPatterns("/*");
        return registrationBean;
    }

}
