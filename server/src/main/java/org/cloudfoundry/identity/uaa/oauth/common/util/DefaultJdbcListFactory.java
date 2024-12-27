package org.cloudfoundry.identity.uaa.oauth.common.util;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;

import java.util.List;
import java.util.Map;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 utils
 */
public class DefaultJdbcListFactory implements JdbcListFactory {

    private final NamedParameterJdbcOperations jdbcTemplate;

    /**
     * @param jdbcTemplate the jdbc template to use
     */
    public DefaultJdbcListFactory(NamedParameterJdbcOperations jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public <T> List<T> getList(String sql, Map<String, Object> parameters, RowMapper<T> rowMapper) {
        return jdbcTemplate.query(sql, parameters, rowMapper);
    }

}
