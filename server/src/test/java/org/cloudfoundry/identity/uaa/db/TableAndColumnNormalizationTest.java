package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.util.beans.PasswordEncoderConfig;
import org.junit.Assume;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ImportResource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.context.WebApplicationContext;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ImportResource(locations = {
        "classpath:spring/env.xml",
        "classpath:spring/use_uaa_db_in_mysql_url.xml", // adds this one
        "classpath:spring/jdbc-test-base-add-flyway.xml",
        "classpath:spring/data-source.xml",
})
class TableAndColumnNormalizationTestConfiguration {
}

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = {
        TableAndColumnNormalizationTestConfiguration.class,
        PasswordEncoderConfig.class,
})
class TableAndColumnNormalizationTest {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private DataSource dataSource;

    @BeforeEach
    void checkMysqlOrPostgresqlProfile(
            @Autowired WebApplicationContext webApplicationContext
    ) {
        Assume.assumeTrue(
                Arrays.asList(webApplicationContext.getEnvironment().getActiveProfiles()).contains("mysql") ||
                        Arrays.asList(webApplicationContext.getEnvironment().getActiveProfiles()).contains("postgresql")
        );
    }

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
                            String.format("Table[%s] is not lower case.", name));
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
                    assertEquals(String.format("Column[%s.%s] is not lower case.", name, col), col.toLowerCase(), col);
                }
            }
            assertTrue(hadSomeResults, "Getting columns from db metadata should have returned some results");
        }
    }
}
