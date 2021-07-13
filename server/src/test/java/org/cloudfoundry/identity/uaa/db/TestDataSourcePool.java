package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;

@WithDatabaseContext
class TestDataSourcePool {

    @Autowired
    @Qualifier("validationQuery")
    private String validationQuery;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void testValidationQuery() {
        int i = jdbcTemplate.queryForObject(this.validationQuery, Integer.class);
        assertEquals(1, i);
    }

}
