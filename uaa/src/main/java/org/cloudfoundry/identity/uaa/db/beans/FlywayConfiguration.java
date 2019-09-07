package org.cloudfoundry.identity.uaa.db.beans;

import org.cloudfoundry.identity.uaa.db.DataSourceAccessor;
import org.cloudfoundry.identity.uaa.db.FixFailedBackportMigrations_4_0_4;
import org.cloudfoundry.identity.uaa.db.postgresql.V1_5_3__InitialDBScript;
import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

@Configuration
public class FlywayConfiguration {

    /**
     * In Flyway 5, the default version table name changed to flyway_schema_history
     * https://flywaydb.org/documentation/releaseNotes#5.0.0
     * https://github.com/flyway/flyway/issues/1848
     *
     * We need to maintain backwards compatibility due to {@link FixFailedBackportMigrations_4_0_4}
     */
    static final String VERSION_TABLE = "schema_version";

    /**
     * @param dataSourceAccessor This bean does NOT need need an instance of {@link DataSourceAccessor}.
     *                           However, other Flyway objects (example {@link V1_5_3__InitialDBScript}
     *                           DO make use of {@link DataSourceAccessor}
     */
    @Bean
    public Flyway flyway(
            DataSource dataSource,
            DataSourceAccessor dataSourceAccessor,
            @Qualifier("platform") String platform) {
        Flyway flyway = Flyway.configure()
                .baselineOnMigrate(true)
                .dataSource(dataSource)
                .locations("classpath:org/cloudfoundry/identity/uaa/db/" + platform + "/")
                .baselineVersion("1.5.2")
                .validateOnMigrate(false)
                .table(VERSION_TABLE)
                .load();
        flyway.repair();
        flyway.migrate();
        return flyway;
    }
}
