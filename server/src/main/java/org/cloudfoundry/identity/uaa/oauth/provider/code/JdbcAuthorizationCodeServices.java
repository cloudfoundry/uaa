package org.cloudfoundry.identity.uaa.oauth.provider.code;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.SqlLobValue;
import org.cloudfoundry.identity.uaa.oauth.common.util.SerializationUtils;
import org.springframework.util.Assert;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class JdbcAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {

    private static final String DEFAULT_SELECT_STATEMENT = "select code, authentication from oauth_code where code = ?";
    private static final String DEFAULT_INSERT_STATEMENT = "insert into oauth_code (code, authentication) values (?, ?)";
    private static final String DEFAULT_DELETE_STATEMENT = "delete from oauth_code where code = ?";

    private String selectAuthenticationSql = DEFAULT_SELECT_STATEMENT;
    private String insertAuthenticationSql = DEFAULT_INSERT_STATEMENT;
    private String deleteAuthenticationSql = DEFAULT_DELETE_STATEMENT;

    private final JdbcTemplate jdbcTemplate;

    public JdbcAuthorizationCodeServices(DataSource dataSource) {
        Assert.notNull(dataSource, "DataSource required");
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    protected void store(String code, OAuth2Authentication authentication) {
        jdbcTemplate.update(insertAuthenticationSql,
                new Object[]{code, new SqlLobValue(SerializationUtils.serialize(authentication))}, new int[]{
                        Types.VARCHAR, Types.BLOB});
    }

    public OAuth2Authentication remove(String code) {
        OAuth2Authentication authentication;

        try {
            authentication = jdbcTemplate.queryForObject(selectAuthenticationSql,
                    new RowMapper<OAuth2Authentication>() {
                        public OAuth2Authentication mapRow(ResultSet rs, int rowNum)
                                throws SQLException {
                            return SerializationUtils.deserialize(rs.getBytes("authentication"));
                        }
                    }, code);
        } catch (EmptyResultDataAccessException e) {
            return null;
        }

        if (authentication != null) {
            jdbcTemplate.update(deleteAuthenticationSql, code);
        }

        return authentication;
    }

    public void setSelectAuthenticationSql(String selectAuthenticationSql) {
        this.selectAuthenticationSql = selectAuthenticationSql;
    }

    public void setInsertAuthenticationSql(String insertAuthenticationSql) {
        this.insertAuthenticationSql = insertAuthenticationSql;
    }

    public void setDeleteAuthenticationSql(String deleteAuthenticationSql) {
        this.deleteAuthenticationSql = deleteAuthenticationSql;
    }
}
