package org.cloudfoundry.identity.uaa.db;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class DatabaseParametersTests extends JdbcTestBase {


    private Vendor vendor;

    @Override
    @Before
    public void setUp() {
        MockEnvironment environment = new MockEnvironment();
        environment.setProperty("database.initialsize", "0");
        environment.setProperty("database.validationquerytimeout", "5");
        environment.setProperty("database.connecttimeout", "5");
        if (System.getProperty("spring.profiles.active")!=null) {
            environment.setActiveProfiles(StringUtils.commaDelimitedListToStringArray(System.getProperty("spring.profiles.active")));
        }
        super.setUp(environment);
        vendor = webApplicationContext.getBean(DatabaseUrlModifier.class).getDatabaseType();
    }

    @Test
    public void initial_size() {
        assertEquals(0, getDataSource().getInitialSize());
    }

    @Test
    public void validation_query_timeout() {
        assertEquals(5, getDataSource().getValidationQueryTimeout());
    }

    @Test
    public void connection_timeout_property_set() throws Exception {
        switch (vendor) {
            case mysql : {
                assertEquals("5000", getUrlParameter("connectTimeout"));
                break;
            }
            case postgresql : {
                assertEquals("5", getUrlParameter("connectTimeout"));
                break;
            }
            case hsqldb : {break;}
            default : throw new IllegalStateException("Unrecognized database: "+ vendor);
        }

    }

    public DataSource getDataSource() {
        return (DataSource)dataSource;
    }

    public String getUrlParameter(String name) {
        String dburl = getDataSource().getUrl();
        URI uri = URI.create("http://localhost" + dburl.substring(dburl.indexOf("?")));
        List<NameValuePair> pairs = URLEncodedUtils.parse(uri, StandardCharsets.UTF_8);
        for (NameValuePair p : pairs) {
            if (name.equals(p.getName())) {
                return p.getValue();
            }
        }
        return null;
    }

}
