package org.cloudfoundry.identity.uaa.db;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@WithDatabaseContext
@TestPropertySource(properties = {
        "database.initialsize=0",
        "database.validationquerytimeout=5",
        "database.connecttimeout=5",
})
class DatabaseParametersTests {

    private Vendor vendor;

    @Autowired
    private DataSource dataSource;

    @BeforeEach
    void setUp(@Autowired DatabaseUrlModifier databaseUrlModifier) {
        vendor = databaseUrlModifier.getDatabaseType();
    }

    @Test
    void initial_size() {
        assertEquals(0, dataSource.getInitialSize());
    }

    @Test
    void validation_query_timeout() {
        assertEquals(5, dataSource.getValidationQueryTimeout());
    }

    @Test
    void connection_timeout_property_set() {
        switch (vendor) {
            case mysql: {
                assertEquals("5000", getUrlParameter("connectTimeout"));
                break;
            }
            case postgresql: {
                assertEquals("5", getUrlParameter("connectTimeout"));
                break;
            }
            case hsqldb: {
                break;
            }
            default:
                throw new IllegalStateException("Unrecognized database: " + vendor);
        }

    }

    String getUrlParameter(String name) {
        String dburl = dataSource.getUrl();
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
