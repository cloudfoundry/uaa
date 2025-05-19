package org.cloudfoundry.experimental.boot;

import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.ApplicationContextFacade;
import org.apache.catalina.core.StandardContext;
import org.apache.tomcat.util.descriptor.web.ErrorPage;
import org.cloudfoundry.identity.uaa.UaaApplicationConfiguration;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import java.io.File;
import java.lang.reflect.Field;

import static org.springframework.util.ReflectionUtils.findField;
import static org.springframework.util.ReflectionUtils.getField;

@SpringBootApplication
@Import({UaaBootConfiguration.class, UaaApplicationConfiguration.class})
public class UaaBootApplication {
    public static void main(String... args) {
        String base = System.getProperty("user.dir");

        //set up tomcat base directory
        String tomcatBase = base + "/scripts/boot/tomcat/";
        new File(tomcatBase+"/work").mkdirs();
        new File(tomcatBase+"/webapps").mkdirs();
        System.setProperty("server.tomcat.basedir", tomcatBase);

        //read the uaa.yml file out of the scripts/cargo dir
        String configPath = base + "/scripts/cargo";
        System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", configPath);

        //make spring boot work with UAA beans
        System.setProperty("spring.main.allow-bean-definition-overriding", "true");
        System.setProperty("spring.main.allow-circular-references", "true");
        System.setProperty("server.servlet.context-path", "/uaa");

        //configure sample properties for testing
        System.setProperty("smtp.host", "localhost");
        System.setProperty("smtp.port", "2525");
        System.setProperty("java.security.egd", "file:/dev/./urandom");
        System.setProperty("spring.profiles.active", "hsqldb");

        //debug spring filters
        //System.setProperty("logging.level.org.springframework.security", "TRACE");


        //start the application
        SpringApplication application = new SpringApplication(UaaBootApplication.class);
        application.addInitializers(new YamlServletProfileInitializer());
        application.run(args);
    }

}

//@Configuration
//class UaaSampleAppConfiguration {
//    @Bean
//    public TomcatServletWebServerFactory tomcatServletWebServerFactory() {
//        return new TomcatServletWebServerFactory() {
//            @Override
//            protected TomcatWebServer getTomcatWebServer(Tomcat tomcat) {
//                String base = System.getProperty("user.dir");
//                String configPath = base + "/scripts/cargo";
//                System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", configPath);
//                String app = base + "/samples/app/build/libs/cloudfoundry-identity-app-0.0.0.war";
//                String api = base + "/samples/api/build/libs/cloudfoundry-identity-api-0.0.0.war";
//                for (String path : asList(app, api)) {
//                    File f = new File(path);
//                    if (!f.exists()) {
//                        throw new UnsupportedOperationException(f.getAbsolutePath() + " does not exist. Please run `./gradlew assemble`.");
//                    }
//                }
//                tomcat.addWebapp("/app", app);
//                tomcat.addWebapp("/api", api);
//                return super.getTomcatWebServer(tomcat);
//            }
//        };
//    }
//}

@Configuration
class UaaBootConfiguration implements ServletContextInitializer, WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        String base = System.getProperty("user.dir");
        registry.addResourceHandler("/**")
                .addResourceLocations("file:"+base+"/uaa/src/main/webapp/");
    }

    @Bean
    WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> enableDefaultServlet() {
        return (factory) -> factory.setRegisterDefaultServlet(true);
    }

    @Bean
    DelegatingFilterProxyRegistrationBean springSessionRepositoryFilterRegistration() {
        return new DelegatingFilterProxyRegistrationBean(
                "springSessionRepositoryFilter"
        );
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {
        HttpSessionEventPublisher publisher = new HttpSessionEventPublisher();
        servletContext.addListener(publisher);

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

