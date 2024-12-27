package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.db.mysql.V1_5_4__NormalizeTableAndColumnNames;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.extensions.profiles.EnabledIfProfile;
import org.cloudfoundry.identity.uaa.util.beans.PasswordEncoderConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.env.MapPropertySource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ImportResource(locations = {
        "classpath:spring/env.xml",
        "classpath:spring/jdbc-test-base-add-flyway.xml",
        "classpath:spring/data-source.xml",
})
class TableAndColumnNormalizationTestConfiguration {
}

/**
 * For MySQL, the database name is hardcoded in the {@link V1_5_4__NormalizeTableAndColumnNames} migration as
 * {@code uaa}. But the {@link UaaDatabaseName} class dynamically allocates a DB name based on the gradle worker id,
 * like {@code uaa_1, uaa_2m ...}.
 * <p>
 * When the profile is {@code mysql}, hardcode the DB url to have the database name equal to {@code uaa}.
 */
class MySQLInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        var profiles = Arrays.asList(applicationContext.getEnvironment().getActiveProfiles());
        if (profiles.contains("mysql")) {
            Map<String, Object> dynamicProperties = Map.of("database.url", "jdbc:mysql://127.0.0.1:3306/uaa?useSSL=true&trustServerCertificate=true");
            MapPropertySource propertySource = new MapPropertySource("mysql-override", dynamicProperties);
            applicationContext.getEnvironment().getPropertySources().addLast(propertySource);
        }
    }
}

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@ContextConfiguration(classes = {
        TableAndColumnNormalizationTestConfiguration.class,
        PasswordEncoderConfig.class
},
        initializers = MySQLInitializer.class
)
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
                logger.info("Checking table [" + name + "]");
                if (name != null && DatabaseInformation1_5_3.tableNames.contains(name.toLowerCase())) {
                    count++;
                    logger.info("Validating table [" + name + "]");
                    assertEquals(name.toLowerCase(),
                            name,
                            "Table[%s] is not lower case.".formatted(name));
                }
            }
            assertEquals(DatabaseInformation1_5_3.tableNames.size(), count, "Table count:");
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
                logger.info("Checking column [" + name + "." + col + "]");
                if (name != null && DatabaseInformation1_5_3.tableNames.contains(name.toLowerCase())) {
                    logger.info("Validating column [" + name + "." + col + "]");
                    assertEquals(col.toLowerCase(), col, "Column[%s.%s] is not lower case.".formatted(name, col));
                }
            }
            assertTrue(hadSomeResults, "Getting columns from db metadata should have returned some results");
        }
    }

}
