package org.cloudfoundry.identity.uaa;

import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.ApplicationContextFacade;
import org.apache.catalina.core.StandardContext;
import org.apache.tomcat.util.descriptor.web.ErrorPage;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.DispatcherServlet;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterRegistration;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRegistration;
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

        //<filter-name>springSessionRepositoryFilter</filter-name>
        DelegatingFilterProxy springSessionRepositoryFilter = new DelegatingFilterProxy("springSessionRepositoryFilter", context);
        FilterRegistration.Dynamic springSessionRepositoryFilterRegistration = servletContext.addFilter(
                "springSessionRepositoryFilter", springSessionRepositoryFilter
        );
        springSessionRepositoryFilterRegistration.addMappingForUrlPatterns(
                EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR), false, "/*"
        );

        //<filter-name>aggregateSpringSecurityFilterChain</filter-name>
        DelegatingFilterProxy springSecurityFilterChain = new DelegatingFilterProxy("springSecurityFilterChain", context);
        FilterRegistration.Dynamic springSecurityFilterChainRegistration = servletContext.addFilter(
                "springSecurityFilterChain",  springSecurityFilterChain
        );
        springSecurityFilterChainRegistration.setInitParameter(
                "contextAttribute", "org.springframework.web.servlet.FrameworkServlet.CONTEXT.spring"
        );
        springSecurityFilterChainRegistration.addMappingForUrlPatterns(null, false, "/*");

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
            error404.setErrorCode(404);
            error404.setLocation("/error404");
            standardContext.addErrorPage(error404);

            ErrorPage error429 = new ErrorPage();
            error429.setErrorCode(429);
            error429.setLocation("/error429");
            standardContext.addErrorPage(error429);

            ErrorPage error = new ErrorPage();
            error.setLocation("/error");
            standardContext.addErrorPage(error);
        }
    }
}
