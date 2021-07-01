package org.cloudfoundry.identity.uaa.oauth.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN;
import static org.springframework.util.StringUtils.isEmpty;

public class JdbcRevocableTokenProvisioning implements RevocableTokenProvisioning, SystemDeletable {

    private final static String REFRESH_TOKEN_RESPONSE_TYPE = REFRESH_TOKEN.toString();
    private final static String FIELDS = "token_id,client_id,user_id,format,response_type,issued_at,expires_at,scope,data,identity_zone_id";
    private final static String UPDATE_FIELDS = FIELDS.substring(FIELDS.indexOf(',') + 1, FIELDS.lastIndexOf(',')).replace(",", "=?,") + "=?";
    private final static String TABLE = "revocable_tokens";
    private static final String SELECT = "SELECT ";
    private static final String FROM = " FROM ";
    private final static String GET_QUERY = "SELECT " + FIELDS + " FROM " + TABLE + " WHERE token_id=? AND identity_zone_id=?";
    private final static String GET_COUNT_QUERY = "SELECT COUNT(*) FROM " + TABLE + " WHERE token_id=? AND identity_zone_id=?";
    private final static String GET_BY_USER_QUERY = "SELECT " + FIELDS + " FROM " + TABLE + " WHERE user_id=? AND identity_zone_id=?";
    private final static String GET_BY_CLIENT_QUERY = "SELECT " + FIELDS + " FROM " + TABLE + " WHERE client_id=? AND identity_zone_id=?";
    private final static String UPDATE_QUERY = "UPDATE " + TABLE + " SET " + UPDATE_FIELDS + " WHERE token_id=? and identity_zone_id=?";
    private final static String INSERT_QUERY = "INSERT INTO " + TABLE + " (" + FIELDS + ") VALUES (?,?,?,?,?,?,?,?,?,?)";
    private final static String DELETE_QUERY = "DELETE FROM " + TABLE + " WHERE token_id=? and identity_zone_id=?";
    private final static String DELETE_REFRESH_TOKEN_QUERY = "DELETE FROM " + TABLE + " WHERE user_id=? AND client_id=? AND response_type='" + REFRESH_TOKEN_RESPONSE_TYPE + "' AND identity_zone_id=?";
    private final static String DELETE_BY_CLIENT_QUERY = "DELETE FROM " + TABLE + " WHERE client_id = ? AND identity_zone_id=?";
    private final static String DELETE_BY_USER_QUERY = "DELETE FROM " + TABLE + " WHERE user_id = ? AND identity_zone_id=?";
    private final static String DELETE_BY_ZONE_QUERY = "DELETE FROM " + TABLE + " WHERE identity_zone_id=?";

    private final static Logger logger = LoggerFactory.getLogger(JdbcRevocableTokenProvisioning.class);
    private final RowMapper<RevocableToken> rowMapper;
    private final JdbcTemplate template;
    private final LimitSqlAdapter limitSqlAdapter;
    private TimeService timeService;

    private AtomicLong lastExpiredCheck = new AtomicLong(0);
    private Duration maxExpirationRuntime = Duration.ofMillis(2500L);
    private final static Duration EXPIRATION_CHECK_INTERVAL = Duration.ofSeconds(30);

    public JdbcRevocableTokenProvisioning(JdbcTemplate jdbcTemplate,
                                          LimitSqlAdapter limitSqlAdapter,
                                          TimeService timeService) {
        this.rowMapper = new RevocableTokenRowMapper();
        this.template = jdbcTemplate;
        this.limitSqlAdapter = limitSqlAdapter;
        this.timeService = timeService;
    }

    @Override
    public List<RevocableToken> retrieveAll(String zoneId) {
        return null;
    }

    private boolean exists(String id, boolean checkExpired, String zoneId) {
        if (checkExpired) {
            checkExpired();
        }
        Integer idResults = template.queryForObject(GET_COUNT_QUERY, Integer.class, id, zoneId);
        return idResults != null && idResults == 1;
    }

    public RevocableToken retrieve(String id, boolean checkExpired, String zoneId) {
        if (checkExpired) {
            checkExpired();
        }
        RevocableToken result = template.queryForObject(GET_QUERY, rowMapper, id, zoneId);
        if (checkExpired && result.getExpiresAt() < timeService.getCurrentTimeMillis()) {
            delete(id, 0, zoneId);
            throw new EmptyResultDataAccessException("Token expired.", 1);
        }
        return result;
    }

    @Override
    public RevocableToken retrieve(String id, String zoneId) {
        return retrieve(id, true, zoneId);
    }

    @Override
    public int deleteRefreshTokensForClientAndUserId(String clientId, String userId, String zoneId) {
        return template.update(DELETE_REFRESH_TOKEN_QUERY, userId, clientId, zoneId);
    }

    public void createIfNotExists(RevocableToken t, String zoneId) {
        if (exists(t.getTokenId(), true, zoneId)) {
            return;
        }
        template.update(INSERT_QUERY,
                t.getTokenId(),
                t.getClientId(),
                t.getUserId(),
                t.getFormat(),
                t.getResponseType().toString(),
                t.getIssuedAt(),
                t.getExpiresAt(),
                t.getScope(),
                t.getValue(),
                zoneId);
    }

    @Override
    public RevocableToken create(RevocableToken t, String zoneId) {
        checkExpired();
        template.update(INSERT_QUERY,
                t.getTokenId(),
                t.getClientId(),
                t.getUserId(),
                t.getFormat(),
                t.getResponseType().toString(),
                t.getIssuedAt(),
                t.getExpiresAt(),
                t.getScope(),
                t.getValue(),
                zoneId);
        return retrieve(t.getTokenId(), false, zoneId);
    }

    @Override
    public RevocableToken update(String id, RevocableToken t, String zoneId) {
        template.update(UPDATE_QUERY,
                t.getClientId(),
                t.getUserId(),
                t.getFormat(),
                t.getResponseType().toString(),
                t.getIssuedAt(),
                t.getExpiresAt(),
                t.getScope(),
                t.getValue(),
                id,
                zoneId);
        return retrieve(id, false, zoneId);
    }

    public void upsert(String id, RevocableToken t, String zoneId) {
        if (exists(t.getTokenId(), true, zoneId)) {
            template.update(UPDATE_QUERY, // NOSONAR
                    t.getClientId(),
                    t.getUserId(),
                    t.getFormat(),
                    t.getResponseType().toString(),
                    t.getIssuedAt(),
                    t.getExpiresAt(),
                    t.getScope(),
                    t.getValue(),
                    id,
                    zoneId);
        } else {
            template.update(INSERT_QUERY,
                    t.getTokenId(),
                    t.getClientId(),
                    t.getUserId(),
                    t.getFormat(),
                    t.getResponseType().toString(),
                    t.getIssuedAt(),
                    t.getExpiresAt(),
                    t.getScope(),
                    t.getValue(),
                    zoneId);
        }
    }

    @Override
    public RevocableToken delete(String id, int version, String zoneId) {
        RevocableToken previous = retrieve(id, false, zoneId);
        template.update(DELETE_QUERY, id, zoneId);
        return previous;
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        return template.update(DELETE_BY_ZONE_QUERY, zoneId);
    }

    @Override
    public int deleteByClient(String clientId, String zoneId) {
        return template.update(DELETE_BY_CLIENT_QUERY, clientId, zoneId);
    }

    @Override
    public int deleteByUser(String userId, String zoneId) {
        return template.update(DELETE_BY_USER_QUERY, userId, zoneId);
    }

    @Override
    public Logger getLogger() {
        return logger;
    }

    @Override
    public List<RevocableToken> getUserTokens(String userId, String zoneId) {
        return template.query(GET_BY_USER_QUERY, rowMapper, userId, zoneId);
    }

    @Override
    public List<RevocableToken> getUserTokens(String userId, String clientId, String zoneId) {
        if (isEmpty(clientId)) {
            throw new NullPointerException("Client ID can not be null when retrieving tokens.");
        }
        return getUserTokens(userId, zoneId).stream().filter(r -> clientId.equals(r.getClientId())).collect(Collectors.toList());
    }

    @Override
    public List<RevocableToken> getClientTokens(String clientId, String zoneId) {
        return template.query(GET_BY_CLIENT_QUERY, rowMapper, clientId, zoneId);
    }

    private void checkExpired() {
        long now = timeService.getCurrentTimeMillis();
        long lastCheck = lastExpiredCheck.get();
        if ((now - lastCheck) > EXPIRATION_CHECK_INTERVAL.toMillis() && lastExpiredCheck.compareAndSet(lastCheck, now)) {
            if (runDeleteExpired(now)) {
                resetLastExpiredCheck();
            }
        }
    }

    void resetLastExpiredCheck() {
        lastExpiredCheck.set(0);
    }

    /**
     * @param now
     * @return true if the last delete action deleted the max rows, this also signals there could be more rows to be deleted.
     */
    private boolean runDeleteExpired(long now) {
        final int maxRows = 500;
        String sql = limitSqlAdapter.getDeleteExpiredQuery(
                TABLE, "token_id", "expires_at", maxRows
        );
        int removed;
        do {
            removed = template.update(sql, now);
            logger.info("Removed " + removed + " expired revocable tokens.");
        } while (removed > 0 && (timeService.getCurrentTimeMillis() - now) < maxExpirationRuntime.toMillis());
        return removed >= maxRows;
    }

    public void setMaxExpirationRuntime(long maxExpirationRuntime) {
        this.maxExpirationRuntime = Duration.ofMillis(maxExpirationRuntime);
    }

    protected static final class RevocableTokenRowMapper implements RowMapper<RevocableToken> {

        @Override
        public RevocableToken mapRow(ResultSet rs, int rowNum) throws SQLException {
            int pos = 1;

            RevocableToken revocableToken = new RevocableToken();
            revocableToken.setTokenId(rs.getString(pos++));
            revocableToken.setClientId(rs.getString(pos++));
            revocableToken.setUserId(rs.getString(pos++));
            revocableToken.setFormat(rs.getString(pos++));
            String responseType = rs.getString(pos++);
            if (StringUtils.hasText(responseType)) {
                revocableToken.setResponseType(RevocableToken.TokenType.valueOf(responseType));
            }
            revocableToken.setIssuedAt(rs.getLong(pos++));
            revocableToken.setExpiresAt(rs.getLong(pos++));
            revocableToken.setScope(rs.getString(pos++));
            revocableToken.setValue(rs.getString(pos++));
            revocableToken.setZoneId(rs.getString(pos++));
            return revocableToken;
        }
    }

    public void setTimeService(TimeService timeService) {
        this.timeService = timeService;
    }
}
