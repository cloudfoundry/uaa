package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.impl.config.YamlConfigurationValidator;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import jakarta.validation.ConstraintViolationException;
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


    static class TestApplicationContext extends AnnotationConfigWebApplicationContext {

        @Override
        protected void loadBeanDefinitions(@NonNull DefaultListableBeanFactory beanFactory) throws BeansException {
            this.scan("org.cloudfoundry.identity.uaa");
            super.loadBeanDefinitions(beanFactory);
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
