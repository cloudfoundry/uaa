package org.cloudfoundry.identity.uaa.db;

import org.apache.hc.core5.net.URLEncodedUtils;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.db.beans.DatabaseProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@WithDatabaseContext
@TestPropertySource(properties = {
        "database.initialsize=0",
        "database.validationquerytimeout=5",
        "database.connecttimeout=5",
        "database.testwhileidle=true",
})
class DatabaseParametersTests {

    @Autowired
    DatabaseProperties databaseProperties;

    @Autowired
    private DataSource dataSource;

    @Test
    void initial_size() {
        assertThat(dataSource.getInitialSize()).isZero();
    }

    @Test
    void validation_query_timeout() {
        assertThat(dataSource.getValidationQueryTimeout()).isEqualTo(5);
    }

    @Test
    void testWhileIdle() {
        assertThat(dataSource.isTestWhileIdle()).isTrue();
    }

    @Test
    void connection_timeout_property_set() {
        switch (databaseProperties.getDatabasePlatform()) {
            case MYSQL: {
                assertThat(getUrlParameter("connectTimeout")).isEqualTo("5000");
                break;
            }
            case POSTGRESQL: {
                assertThat(getUrlParameter("connectTimeout")).isEqualTo("5");
                break;
            }
            case HSQLDB:
                // For in-memory HSQLDB, the timeout MAY be present but is irrelevant
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
