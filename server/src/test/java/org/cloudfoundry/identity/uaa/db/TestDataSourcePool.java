package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class TestDataSourcePool extends JdbcTestBase {

    @Test
    public void testValidationQuery() {
        int i = jdbcTemplate.queryForObject(this.validationQuery, Integer.class);
        assertEquals(1, i);
    }

}
