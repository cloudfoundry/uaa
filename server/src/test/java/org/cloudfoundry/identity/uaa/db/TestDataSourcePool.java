package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.db.beans.DatabaseProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

@WithDatabaseContext
class TestDataSourcePool {

    @Autowired
    private DatabaseProperties databaseProperties;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void validationQuery() {
        int i = jdbcTemplate.queryForObject(this.databaseProperties.getValidationQuery(), Integer.class);
        assertThat(i).isOne();
    }

}
