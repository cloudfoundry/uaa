package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.UUID;

@WithDatabaseContext
@Transactional
class SpringSessionAttributesTableTest {
    @Autowired
    private JdbcTemplate jdbcTemplate;
    private String primaryId;
    private String sessionId;

    @BeforeEach
    void setUp() {
        primaryId = UUID.randomUUID().toString();
        sessionId = UUID.randomUUID().toString();
        jdbcTemplate.update(
                "insert into SPRING_SESSION (PRIMARY_ID, SESSION_ID, CREATION_TIME, LAST_ACCESS_TIME, MAX_INACTIVE_INTERVAL, EXPIRY_TIME) values (?, ?, ?, ?, ?, ?)",
                primaryId, sessionId, 0, 0, 2000, 6000);
    }

    @ParameterizedTest
    @ValueSource(ints = {3000, 150000})
    void attributeBytesColumn(int valueSize) {
        byte[] attributeBytes = new byte[valueSize];
        Arrays.fill(attributeBytes, (byte) 65);
        jdbcTemplate.update(
                "insert into SPRING_SESSION_ATTRIBUTES (SESSION_PRIMARY_ID, ATTRIBUTE_NAME, ATTRIBUTE_BYTES) values (?, ?, ?)",
                primaryId, "my_attribute_name", attributeBytes);
        jdbcTemplate.query(
                "select ATTRIBUTE_BYTES from SPRING_SESSION_ATTRIBUTES where SESSION_PRIMARY_ID = ?",
                rs -> {
                    Assertions.assertEquals(valueSize, rs.getBytes(1).length);
                },
                primaryId);
    }
}
