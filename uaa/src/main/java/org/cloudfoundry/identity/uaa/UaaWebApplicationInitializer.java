package org.cloudfoundry.identity.uaa;

import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.ApplicationContextFacade;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.filters.HttpHeaderSecurityFilter;
import org.apache.tomcat.util.descriptor.web.ErrorPage;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.ratelimiting.RateLimitingFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.RequestContextFilter;
import org.springframework.web.servlet.DispatcherServlet;

import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;
import java.lang.reflect.Field;
import java.util.EnumSet;

import static org.springframework.util.ReflectionUtils.findField;
import static org.springframework.util.ReflectionUtils.getField;

public class UaaWebApplicationInitializer implements WebApplicationInitializer {
    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {
        HttpSessionEventPublisher publisher = new HttpSessionEventPublisher();
        servletContext.addListener(publisher);

        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
        context.register(UaaApplicationConfiguration.class);
        context.setServletContext(servletContext);
        ContextLoaderListener contextLoaderListener = new ContextLoaderListener(context);
        contextLoaderListener.setContextInitializers(new YamlServletProfileInitializer());
        servletContext.addListener(contextLoaderListener);

        //<filter-name>rateLimitingFilter</filter-name>
        FilterRegistration.Dynamic rateLimitingRegistration = servletContext.addFilter(
                "rateLimitingFilter", new RateLimitingFilter()
        );
        rateLimitingRegistration.addMappingForUrlPatterns(null, false, "/*");
        rateLimitingRegistration.setInitParameter(
                "contextAttribute",
                "org.springframework.web.servlet.FrameworkServlet.CONTEXT.spring"
        );

        //<filter-name>springSessionRepositoryFilter</filter-name>
        DelegatingFilterProxy springSessionRepositoryFilter = new DelegatingFilterProxy("springSessionRepositoryFilter", context);
        FilterRegistration.Dynamic springSessionRepositoryFilterRegistration = servletContext.addFilter(
                "springSessionRepositoryFilter", springSessionRepositoryFilter
        );
        springSessionRepositoryFilterRegistration.addMappingForUrlPatterns(
                EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR), false, "/*"
        );

        //<filter-name>springRequestContextFilter</filter-name>
        RequestContextFilter springRequestContextFilter = new RequestContextFilter();
        FilterRegistration.Dynamic springRequestContextFilterRegistration = servletContext.addFilter(
                "springRequestContextFilter", springRequestContextFilter
        );
        springRequestContextFilterRegistration.addMappingForUrlPatterns(null, false, "/*");

        //<filter-name>aggregateSpringSecurityFilterChain</filter-name>
        DelegatingFilterProxy aggregateSpringSecurityFilterChain = new DelegatingFilterProxy("aggregateSpringSecurityFilterChain", context);
        FilterRegistration.Dynamic aggregateSpringSecurityFilterChainRegistration = servletContext.addFilter(
                "aggregateSpringSecurityFilterChain",  aggregateSpringSecurityFilterChain
        );
        aggregateSpringSecurityFilterChainRegistration.setInitParameter(
                "contextAttribute", "org.springframework.web.servlet.FrameworkServlet.CONTEXT.spring"
        );
        aggregateSpringSecurityFilterChainRegistration.addMappingForUrlPatterns(null, false, "/*");

        //<filter-name>HttpHeaderSecurityFilter</filter-name>
        HttpHeaderSecurityFilter httpHeaderSecurityFilter = new HttpHeaderSecurityFilter();
        httpHeaderSecurityFilter.setHstsEnabled(false);
        httpHeaderSecurityFilter.setAntiClickJackingEnabled(false);
        httpHeaderSecurityFilter.setBlockContentTypeSniffingEnabled(true);
        httpHeaderSecurityFilter.setXssProtectionEnabled(false);
        FilterRegistration.Dynamic httpHeaderSecurityFilterRegistration = servletContext.addFilter(
                "HttpHeaderSecurityFilter", httpHeaderSecurityFilter
        );
        httpHeaderSecurityFilterRegistration.addMappingForUrlPatterns(null, false, "/*");

        //<servlet-name>spring</servlet-name>
        DispatcherServlet spring = new DispatcherServlet(context);
        spring.setDispatchTraceRequest(false);
        ServletRegistration.Dynamic springRegistration = servletContext.addServlet("spring", spring);
        springRegistration.setLoadOnStartup(1);
        springRegistration.addMapping("/");

        //<error-page> from web.xml
        if (servletContext instanceof ApplicationContextFacade) {
            Field field = findField(ApplicationContextFacade.class, "context", ApplicationContext.class);
            field.setAccessible(true);
            ApplicationContext applicationContext = (ApplicationContext) getField(field, servletContext);

            field = findField(ApplicationContext.class, "context", StandardContext.class);
            field.setAccessible(true);
            StandardContext standardContext = (StandardContext) getField(field, applicationContext);

            ErrorPage error500 = new ErrorPage();
            error500.setErrorCode(500);
            error500.setLocation("/error500");
            standardContext.addErrorPage(error500);

            ErrorPage error404 = new ErrorPage();
            error500.setErrorCode(404);
            error500.setLocation("/error404");
            standardContext.addErrorPage(error404);

            ErrorPage error429 = new ErrorPage();
            error500.setErrorCode(429);
            error500.setLocation("/error429");
            standardContext.addErrorPage(error429);

            ErrorPage error = new ErrorPage();
            error.setLocation("/error");
            standardContext.addErrorPage(error);

            ErrorPage errorEx = new ErrorPage();
            errorEx.setLocation("/rejected");
            errorEx.setExceptionType("org.springframework.security.web.firewall.RequestRejectedException");
            standardContext.addErrorPage(errorEx);
        }
    }
}
