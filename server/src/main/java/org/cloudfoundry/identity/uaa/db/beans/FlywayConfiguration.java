package org.cloudfoundry.identity.uaa.db.beans;

import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

@Configuration
public class FlywayConfiguration {
    @Bean
    public Flyway flyway(
            DataSource dataSource,
            @Qualifier("platform") String platform) {
        Flyway flyway = Flyway.configure()
                .baselineOnMigrate(true)
                .dataSource(dataSource)
                .locations("classpath:org/cloudfoundry/identity/uaa/db/" + platform + "/")
                .baselineVersion("1.5.2")
                .validateOnMigrate(false)
                .load();
        flyway.migrate();
        return flyway;
    }

}

