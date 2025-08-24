package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.db.beans.DatabaseConfiguration;
import org.cloudfoundry.identity.uaa.db.beans.FlywayConfiguration;
import org.cloudfoundry.identity.uaa.db.beans.JdbcUrlCustomizer;
import org.cloudfoundry.identity.uaa.db.mysql.V1_5_4__NormalizeTableAndColumnNames;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.extensions.profiles.EnabledIfProfile;
import org.cloudfoundry.identity.uaa.test.TestDatabaseNameCustomizer;
import org.cloudfoundry.identity.uaa.util.beans.PasswordEncoderConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * For MySQL, the database name is hardcoded in the {@link V1_5_4__NormalizeTableAndColumnNames} migration as
 * {@code uaa}. But the {@link TestDatabaseNameCustomizer} class dynamically allocates a DB name based on the
 * gradle worker id, like {@code uaa_1, uaa_2 ...}.
 * <p>
 * When the profile is {@code mysql}, hardcode the DB url to have the database name equal to {@code uaa}.
 * <p>
 * This customizer must happen after {@link TestDatabaseNameCustomizer}, hence the higher order.
 */
@Configuration
class MySQLConfiguration {
    @Bean
    @Order(TestDatabaseNameCustomizer.ORDER + 1)
    @Profile("mysql")
    JdbcUrlCustomizer mysqlHardcodedJdbcUrlCustomizer() {
        return url -> "jdbc:mysql://127.0.0.1:3306/uaa?useSSL=true&trustServerCertificate=true";
    }
}

@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@SpringJUnitConfig(classes = {
        PasswordEncoderConfig.class,
        FlywayConfiguration.class,
        DatabaseConfiguration.class,
        TestDatabaseNameCustomizer.class,
        MySQLConfiguration.class
})
@EnabledIfProfile({"postgresql", "mysql"})
class TableAndColumnNormalizationTest {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private DataSource dataSource;

    @Test
    void checkTables() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metaData = connection.getMetaData();
            ResultSet rs = metaData.getTables(null, null, null, new String[]{"TABLE"});
            int count = 0;
            while (rs.next()) {
                String name = rs.getString("TABLE_NAME");
                logger.info("Checking table [{}]", name);
                if (name != null && DatabaseInformation1_5_3.tableNames.contains(name.toLowerCase())) {
                    count++;
                    logger.info("Validating table [{}]", name);
                    assertThat(name).as("Table[%s] is not lower case.".formatted(name)).isEqualTo(name.toLowerCase());
                }
            }
            assertThat(count).as("Table count:").isEqualTo(DatabaseInformation1_5_3.tableNames.size());
        }
    }

    @Test
    void checkColumns() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metaData = connection.getMetaData();
            ResultSet rs = metaData.getColumns(null, null, null, null);
            boolean hadSomeResults = false;
            while (rs.next()) {
                hadSomeResults = true;
                String name = rs.getString("TABLE_NAME");
                String col = rs.getString("COLUMN_NAME");
                logger.info("Checking column [{}.{}]", name, col);
                if (name != null && DatabaseInformation1_5_3.tableNames.contains(name.toLowerCase())) {
                    logger.info("Validating column [{}.{}]", name, col);
                    assertThat(col.toLowerCase()).as("Column[%s.%s] is not lower case.".formatted(name, col)).isEqualTo(col);
                }
            }
            assertThat(hadSomeResults).as("Getting columns from db metadata should have returned some results").isTrue();
        }
    }
}
