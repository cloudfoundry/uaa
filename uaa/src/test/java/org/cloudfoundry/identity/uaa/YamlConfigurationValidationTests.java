package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.impl.config.YamlConfigurationValidator;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.ResourceEntityResolver;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.support.AbstractRefreshableWebApplicationContext;

import javax.validation.ConstraintViolationException;
import java.util.EventListener;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * This component-level test verifies that {@link YamlConfigurationValidator} is actually
 * wired into the application context and does validate the configuration.
 */
class YamlConfigurationValidationTests {

    @AfterEach
    void tearDown() {
        System.clearProperty("UAA_CONFIG_URL");
    }

    @Test
    void validConfiguration() {
        System.setProperty("UAA_CONFIG_URL", "classpath:integration_test_properties.yml");
        var applicationContext = createApplicationContext();
        assertThatNoException().isThrownBy(applicationContext::refresh);
    }

    @Test
    void invalidConfiguration() {
        System.setProperty("UAA_CONFIG_URL", "classpath:invalid_configuration.yml");
        var applicationContext = createApplicationContext();
        assertThatThrownBy(applicationContext::refresh)
                .isInstanceOf(BeansException.class)
                .getRootCause()
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("database.url: Database url is required");
    }

    private static TestApplicationContext createApplicationContext() {
        var applicationContext = new TestApplicationContext();
        var servletContext = new TestMockContext();
        applicationContext.setServletContext(servletContext);
        MockServletConfig servletConfig = new MockServletConfig(servletContext);
        applicationContext.setServletConfig(servletConfig);

        YamlServletProfileInitializer initializer = new YamlServletProfileInitializer();
        initializer.initialize(applicationContext);
        applicationContext.getEnvironment().setActiveProfiles("strict");
        return applicationContext;
    }


    static class TestApplicationContext extends AbstractRefreshableWebApplicationContext {

        @Override
        protected void loadBeanDefinitions(@NonNull DefaultListableBeanFactory beanFactory) throws BeansException {
            XmlBeanDefinitionReader beanDefinitionReader = new XmlBeanDefinitionReader(beanFactory);

            // Configure the bean definition reader with this context's
            // resource loading environment.
            beanDefinitionReader.setEnvironment(this.getEnvironment());
            beanDefinitionReader.setResourceLoader(this);
            beanDefinitionReader.setEntityResolver(new ResourceEntityResolver(this));

            beanDefinitionReader.loadBeanDefinitions("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        }
    }

    ;

    static class TestMockContext extends MockServletContext {
        @Override
        public <T extends EventListener> void addListener(@Nullable T t) {
            //no op
        }
    }

    ;

}
