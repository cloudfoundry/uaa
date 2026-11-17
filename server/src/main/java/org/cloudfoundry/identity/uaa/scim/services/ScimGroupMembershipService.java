package org.cloudfoundry.identity.uaa.scim.services;

import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.function.Supplier;

@Component
public class ScimGroupMembershipService {

    private final JdbcTemplate jdbcTemplate;
    private final TransactionTemplate transactionTemplate;
    private final String lockSql;

    public ScimGroupMembershipService(JdbcTemplate jdbcTemplate, TransactionTemplate transactionTemplate,
            DbUtils dbUtils) throws SQLException {
        this.jdbcTemplate = jdbcTemplate;
        // Keep the shared template's defaults unchanged; join any caller's transaction.
        this.transactionTemplate = new TransactionTemplate(transactionTemplate.getTransactionManager(), transactionTemplate);
        this.transactionTemplate.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        this.lockSql = "SELECT id FROM " + dbUtils.getQuotedIdentifier("groups", jdbcTemplate)
                + " WHERE id = ? AND identity_zone_id = ? FOR UPDATE";
    }

    /**
     * Runs the callback after locking the zone's group row and holds the lock until transaction completion.
     * Coordinating membership operations must use this helper before their first read. Participates in
     * an existing READ_COMMITTED transaction, so its caller retains control of commit and rollback.
     * Rejects other connection isolation levels before acquiring the lock or invoking the callback.
     */
    public <T> T withLock(String groupId, String zoneId, Supplier<T> operation) {
        return transactionTemplate.execute(_ -> {
            jdbcTemplate.execute((ConnectionCallback<Void>) connection -> {
                if (connection.getTransactionIsolation() != Connection.TRANSACTION_READ_COMMITTED) {
                    throw new IllegalTransactionStateException("Group membership updates require READ_COMMITTED isolation");
                }
                return null;
            });
            if (jdbcTemplate.queryForList(lockSql, String.class, groupId, zoneId).isEmpty()) {
                throw new ScimResourceNotFoundException("Group " + groupId + " not found");
            }
            return operation.get();
        });
    }
}
