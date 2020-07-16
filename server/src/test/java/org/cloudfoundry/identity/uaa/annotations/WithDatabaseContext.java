package org.cloudfoundry.identity.uaa.annotations;

import org.cloudfoundry.identity.uaa.db.beans.FlywayConfiguration;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.util.beans.PasswordEncoderConfig;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.context.annotation.ImportResource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = {
        DatabaseOnlyConfiguration.class,
        PasswordEncoderConfig.class,
        FlywayConfiguration.FlywayConfigurationWithMigration.class,
})
public @interface WithDatabaseContext {

}

@ImportResource(locations = {
        "classpath:spring/env.xml",
        "classpath:spring/data-source.xml",
        "classpath:spring/jdbc-test-base-add-flyway.xml"
})
class DatabaseOnlyConfiguration {

}
