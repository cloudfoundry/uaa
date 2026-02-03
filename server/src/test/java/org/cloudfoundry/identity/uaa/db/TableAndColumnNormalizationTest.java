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
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

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
        return url -> "jdbc:mysql://127.0.0.1:3306/uaa?useSSL=true&trustServerCertificate=true&permitMysqlScheme=true";
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
class TableAndColumnNormalizationTest {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private DataSource dataSource;

    @Test
    @EnabledIfProfile({"postgresql", "mysql"})
    void tableNamesAreLowercase() throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metaData = connection.getMetaData();
            ResultSet rs = metaData.getTables(null, null, null, new String[]{"TABLE"});
            List<String> validatedTables = new ArrayList<>();
            List<String> failures = new ArrayList<>();

            while (rs.next()) {
                String catalog = rs.getString("TABLE_CAT");
                String table = rs.getString("TABLE_NAME");

                logger.info("Checking table [{}.{}]", catalog, table);
                if (isTableInUaaCatalog(catalog, table)) {
                    logger.info("Validating table [{}.{}]", catalog, table);
                    if (table.equals(table.toLowerCase())) {
                        validatedTables.add(table);
                    } else {
                        failures.add("Table[%s.%s] is not lower case.".formatted(catalog, table));
                    }
                }
            }
            assertThat(validatedTables).hasSameElementsAs(DatabaseInformation1_5_3.tableNames);
            assertThat(failures).isEmpty();
        }
    }

    /**
     * Only on postgresql are column names case-sensitive.
     * Column names are not case-sensitive in MySQL on any platform.
     *
     * @throws SQLException
     */
    @Test
    @EnabledIfProfile({"postgresql"})
    void columnNamesAreLowercase() throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metaData = connection.getMetaData();
            ResultSet rs = metaData.getColumns(null, null, null, null);
            boolean hadSomeResults = false;
            List<String> failures = new ArrayList<>();

            while (rs.next()) {
                hadSomeResults = true;
                String catalog = rs.getString("TABLE_CAT");
                String table = rs.getString("TABLE_NAME");
                String col = rs.getString("COLUMN_NAME");
                logger.info("Checking column [{}.{}.{}]", catalog, table, col);

                if (isTableInUaaCatalog(catalog, table)) {
                    logger.info("Validating column [{}.{}]", table, col);
                    if (!col.equals(col.toLowerCase())) {
                        failures.add("Column[%s.%s.%s] is not lower case.".formatted(catalog, table, col));
                    }
                }
            }
            assertThat(hadSomeResults).as("Getting columns from db metadata should have returned some results").isTrue();
            assertThat(failures).isEmpty();
        }
    }

    private static boolean isTableInUaaCatalog(String catalog, String table) {
        return catalog != null
                && catalog.startsWith("uaa")
                && table != null
                && DatabaseInformation1_5_3.tableNames.contains(table.toLowerCase());
    }
}
