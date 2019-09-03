package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.flywaydb.core.Flyway;
import org.junit.After;
import org.junit.Before;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

import javax.sql.DataSource;

import static java.util.Collections.emptyList;

/**
 * @Deprecated. Use {@link WithDatabaseContext} instead.
 * Don't forget to upgrade the tests to JUnit5.
 */
@Deprecated
public class JdbcTestBase extends TestClassNullifier {

    protected XmlWebApplicationContext webApplicationContext;
    protected JdbcTemplate jdbcTemplate;
    protected DataSource dataSource;
    protected LimitSqlAdapter limitSqlAdapter;
    protected MockEnvironment environment;
    protected String validationQuery;

    @Before
    public void setUp() throws Exception {
        IdentityZoneHolder.clear();
        MockEnvironment environment = new MockEnvironment();
        if (System.getProperty("spring.profiles.active") != null) {
            environment.setActiveProfiles(StringUtils.commaDelimitedListToStringArray(System.getProperty("spring.profiles.active")));
        }
        setUp(environment);
    }

    public void setUp(MockEnvironment environment) throws Exception {
        this.environment = environment;
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setEnvironment(environment);
        webApplicationContext.setConfigLocations(getWebApplicationContextConfigFiles());
        webApplicationContext.refresh();
        jdbcTemplate = webApplicationContext.getBean(JdbcTemplate.class);
        dataSource = webApplicationContext.getBean(DataSource.class);
        limitSqlAdapter = webApplicationContext.getBean(LimitSqlAdapter.class);
        validationQuery = webApplicationContext.getBean("validationQuery", String.class);
        IdentityZoneHolder.setProvisioning(new JdbcIdentityZoneProvisioning(jdbcTemplate));
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(emptyList());
    }

    public String[] getWebApplicationContextConfigFiles() {
        return new String[]{
                "classpath:spring/env.xml",
                "classpath:spring/data-source.xml"
        };
    }

    @After
    public void tearDown() {
        TestUtils.restoreToDefaults(webApplicationContext);

        ((org.apache.tomcat.jdbc.pool.DataSource) dataSource).close(true);
        webApplicationContext.destroy();
    }

}
