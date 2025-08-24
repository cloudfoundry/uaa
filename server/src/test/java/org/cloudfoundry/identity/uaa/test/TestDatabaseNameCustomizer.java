package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.db.beans.JdbcUrlCustomizer;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;


/**
 * Update the database name to have one DB per gradle process.
 * To learn more, read docs/testing.md.
 * <p>
 * We are using a "customizer" construct instead of a {@link BeanPostProcessor} because
 * the current {@code spring-servlet} XML configuration initializes some beans eagerly,
 * including the database configuration. The consequence is that they cannot be
 * post-processed, see <a href="https://docs.spring.io/spring-framework/reference/core/beans/factory-extension.html#beans-factory-extension-bpp">BeanPostProcessor instances and AOP auto-proxying</a>.
 */
@Component
@Order(TestDatabaseNameCustomizer.ORDER)
public class TestDatabaseNameCustomizer implements JdbcUrlCustomizer {

    public static final int ORDER = 42;

    public String customize(String url) {
        // If we are not running in gradle, do not customize.
        var gradleWorkerId = System.getProperty("org.gradle.test.worker");
        if (gradleWorkerId == null) {
            return url;
        }

        // If the URL has already been customized, do not update
        var testDatabaseName = "uaa_" + gradleWorkerId;
        if (url.contains(testDatabaseName)) {
            return url;
        }

        // Change the URL name to "uaa_ID"
        return url.replace("uaa", testDatabaseName);
    }
}
