package org.cloudfoundry.identity.uaa.oauth.common.util;

import org.springframework.jdbc.core.RowMapper;
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
public interface JdbcListFactory {

    /**
     * @param sql
     * @param parameters
     * @return a list of {@link T}
     */
    <T> List<T> getList(String sql, Map<String, Object> parameters, RowMapper<T> rowMapper);

}
