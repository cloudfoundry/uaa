package org.cloudfoundry.identity.uaa.user;

import org.apache.commons.lang.ArrayUtils;
import org.cloudfoundry.identity.uaa.db.DatabaseUrlModifier;
import org.cloudfoundry.identity.uaa.db.Vendor;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

import static org.springframework.util.StringUtils.hasText;

public class JdbcUaaUserDatabase implements UaaUserDatabase {

    private static Logger logger = LoggerFactory.getLogger(JdbcUaaUserDatabase.class);

    private static final String USER_FIELDS = "id,username,password,email,givenName,familyName,created,lastModified,authorities,origin,external_id,verified,identity_zone_id,salt,passwd_lastmodified,phoneNumber,legacy_verification_behavior,passwd_change_required,last_logon_success_time,previous_logon_success_time ";

    private static final String PRE_DEFAULT_USER_BY_USERNAME_QUERY = "select " + USER_FIELDS + "from users where %s = ? and active=? and origin=? and identity_zone_id=?";
    static final String DEFAULT_CASE_SENSITIVE_USER_BY_USERNAME_QUERY = String.format(PRE_DEFAULT_USER_BY_USERNAME_QUERY, "lower(username)");
    static final String DEFAULT_CASE_INSENSITIVE_USER_BY_USERNAME_QUERY = String.format(PRE_DEFAULT_USER_BY_USERNAME_QUERY, "username");

    private static final String PRE_DEFAULT_USER_BY_EMAIL_AND_ORIGIN_QUERY = "select " + USER_FIELDS + "from users where %s=? and active=? and origin=? and identity_zone_id=?";
    static final String DEFAULT_CASE_SENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY = String.format(PRE_DEFAULT_USER_BY_EMAIL_AND_ORIGIN_QUERY, "lower(email)");
    static final String DEFAULT_CASE_INSENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY = String.format(PRE_DEFAULT_USER_BY_EMAIL_AND_ORIGIN_QUERY, "email");
    public static final String DEFAULT_UPDATE_USER_LAST_LOGON = "update users set previous_logon_success_time = last_logon_success_time, last_logon_success_time = ? where id = ? and identity_zone_id=?";

    private static final String DEFAULT_USER_BY_ID_QUERY = "select " + USER_FIELDS + "from users where id = ? and active=? and identity_zone_id=?";

    private final TimeService timeService;
    private final JdbcTemplate jdbcTemplate;
    private final boolean caseInsensitive;
    private final IdentityZoneManager identityZoneManager;
    private final DatabaseUrlModifier databaseUrlModifier;

    @Value("${database.maxParameters:-1}")
    private int maxSqlParameters;

    private final RowMapper<UaaUser> mapper = new UaaUserRowMapper();
    private final RowMapper<UaaUserPrototype> minimalMapper = new UaaUserPrototypeRowMapper();
    private final RowMapper<UserInfo> userInfoMapper = new UserInfoRowMapper();

    RowMapper<UaaUser> getMapper() {
        return mapper;
    }

    public JdbcUaaUserDatabase(
            final JdbcTemplate jdbcTemplate,
            final TimeService timeService,
            @Qualifier("useCaseInsensitiveQueries") final boolean caseInsensitive,
            final IdentityZoneManager identityZoneManager,
            final DatabaseUrlModifier databaseUrlModifier) {
        this.jdbcTemplate = jdbcTemplate;
        this.timeService = timeService;
        this.caseInsensitive = caseInsensitive;
        this.identityZoneManager = identityZoneManager;
        this.databaseUrlModifier = databaseUrlModifier;
    }

    public int getMaxSqlParameters() {
        return maxSqlParameters;
    }

    public void setMaxSqlParameters(int maxSqlParameters) {
        this.maxSqlParameters = maxSqlParameters;
    }

    @Override
    public UaaUser retrieveUserByName(String username, String origin) throws UsernameNotFoundException {
        try {
            String sql = caseInsensitive ? DEFAULT_CASE_INSENSITIVE_USER_BY_USERNAME_QUERY : DEFAULT_CASE_SENSITIVE_USER_BY_USERNAME_QUERY;
            return jdbcTemplate.queryForObject(sql, mapper, username.toLowerCase(Locale.US), true, origin, identityZoneManager.getCurrentIdentityZoneId());
        } catch (EmptyResultDataAccessException e) {
            throw new UsernameNotFoundException(username);
        }
    }

    @Override
    public UaaUserPrototype retrieveUserPrototypeByName(String username, String origin) throws UsernameNotFoundException {
        try {
            String sql = caseInsensitive ? DEFAULT_CASE_INSENSITIVE_USER_BY_USERNAME_QUERY : DEFAULT_CASE_SENSITIVE_USER_BY_USERNAME_QUERY;
            return jdbcTemplate.queryForObject(sql, minimalMapper, username.toLowerCase(Locale.US), true, origin, identityZoneManager.getCurrentIdentityZoneId());
        } catch (EmptyResultDataAccessException e) {
            throw new UsernameNotFoundException(username);
        }
    }

    @Override
    public UaaUser retrieveUserById(String id) throws UsernameNotFoundException {
        try {
            return jdbcTemplate.queryForObject(DEFAULT_USER_BY_ID_QUERY, mapper, id, true, identityZoneManager.getCurrentIdentityZoneId());
        } catch (EmptyResultDataAccessException e) {
            throw new UsernameNotFoundException(id);
        }
    }

    @Override
    public UaaUserPrototype retrieveUserPrototypeById(String id) throws UsernameNotFoundException {
        try {
            return jdbcTemplate.queryForObject(DEFAULT_USER_BY_ID_QUERY, minimalMapper, id, true, identityZoneManager.getCurrentIdentityZoneId());
        } catch (EmptyResultDataAccessException e) {
            throw new UsernameNotFoundException(id);
        }
    }

    @Override
    public UaaUser retrieveUserByEmail(String email, String origin) throws UsernameNotFoundException {
        String sql = caseInsensitive ? DEFAULT_CASE_INSENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY : DEFAULT_CASE_SENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY;
        List<UaaUser> results = jdbcTemplate.query(sql, mapper, email.toLowerCase(Locale.US), true, origin, identityZoneManager.getCurrentIdentityZoneId());
        if (results.size() == 0) {
            return null;
        } else if (results.size() == 1) {
            return results.get(0);
        } else {
            throw new IncorrectResultSizeDataAccessException(String.format("Multiple users match email=%s origin=%s", email, origin), 1, results.size());
        }
    }

    @Override
    public UaaUserPrototype retrieveUserPrototypeByEmail(String email, String origin) throws UsernameNotFoundException {
        String sql = caseInsensitive ? DEFAULT_CASE_INSENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY : DEFAULT_CASE_SENSITIVE_USER_BY_EMAIL_AND_ORIGIN_QUERY;
        List<UaaUserPrototype> results = jdbcTemplate.query(sql, minimalMapper, email.toLowerCase(Locale.US), true, origin, identityZoneManager.getCurrentIdentityZoneId());
        if (results.size() == 0) {
            return null;
        } else if (results.size() == 1) {
            return results.get(0);
        } else {
            throw new IncorrectResultSizeDataAccessException(String.format("Multiple users match email=%s origin=%s", email, origin), 1, results.size());
        }
    }

    @Override
    public UserInfo getUserInfo(String id) {
        try {
            return jdbcTemplate.queryForObject("select user_id, info from user_info where user_id = ?", userInfoMapper, id);
        } catch (EmptyResultDataAccessException e) {
            logger.debug("No custom attributes stored for user:" + id);
            return null;
        }
    }

    @Override
    public UserInfo storeUserInfo(String id, UserInfo info) {
        if (StringUtils.isEmpty(id)) {
            throw new NullPointerException("id is a required field");
        }
        final String insertUserInfoSQL = "insert into user_info(user_id, info) values (?,?)";
        final String updateUserInfoSQL = "update user_info set info = ? where user_id = ?";
        if (info == null) {
            info = new UserInfo();
        }
        String json = JsonUtils.writeValueAsString(info);
        int count = jdbcTemplate.update(updateUserInfoSQL, json, id);
        if (count == 0) {
            jdbcTemplate.update(insertUserInfoSQL, id, json);
        }
        return getUserInfo(id);
    }

    @Override
    public void updateLastLogonTime(String userId) {
        jdbcTemplate.update(DEFAULT_UPDATE_USER_LAST_LOGON, timeService.getCurrentTimeMillis(), userId, identityZoneManager.getCurrentIdentityZoneId());
    }

    private UaaUserPrototype getUaaUserPrototype(ResultSet rs) throws SQLException {
        String id = rs.getString("id");
        UaaUserPrototype prototype = new UaaUserPrototype().withId(id)
            .withUsername(rs.getString("username"))
            .withPassword(rs.getString("password"))
            .withEmail(rs.getString("email"))
            .withGivenName(rs.getString("givenName"))
            .withFamilyName(rs.getString("familyName"))
            .withCreated(rs.getTimestamp("created"))
            .withModified(rs.getTimestamp("lastModified"))
            .withOrigin(rs.getString("origin"))
            .withExternalId(rs.getString("external_id"))
            .withVerified(rs.getBoolean("verified"))
            .withZoneId(rs.getString("identity_zone_id"))
            .withSalt(rs.getString("salt"))
            .withPasswordLastModified(rs.getTimestamp("passwd_lastmodified"))
            .withPhoneNumber(rs.getString("phoneNumber"))
            .withLegacyVerificationBehavior(rs.getBoolean("legacy_verification_behavior"))
            .withPasswordChangeRequired(rs.getBoolean("passwd_change_required"));

        Long lastLogon = rs.getLong("last_logon_success_time");
        if (rs.wasNull()) {
            lastLogon = null;
        }
        Long previousLogon = rs.getLong("previous_logon_success_time");
        if (rs.wasNull()) {
            previousLogon = null;
        }
        prototype.withLastLogonSuccess(lastLogon)
            .withPreviousLogonSuccess(previousLogon);
        return prototype;
    }

    private final class UserInfoRowMapper implements RowMapper<UserInfo> {
        @Override
        public UserInfo mapRow(ResultSet rs, int rowNum) throws SQLException {
            String info = rs.getString(2);
            return hasText(info) ? JsonUtils.readValue(info, UserInfo.class) : new UserInfo();
        }
    }

    private final class UaaUserPrototypeRowMapper implements RowMapper<UaaUserPrototype> {
        @Override
        public UaaUserPrototype mapRow(ResultSet rs, int rowNum) throws SQLException {
            return getUaaUserPrototype(rs);
        }
    }

    private final class UaaUserRowMapper implements RowMapper<UaaUser> {
        @Override
        public UaaUser mapRow(ResultSet rs, int rowNum) throws SQLException {
            UaaUserPrototype prototype = getUaaUserPrototype(rs);
            List<GrantedAuthority> authorities =
                AuthorityUtils.commaSeparatedStringToAuthorityList(getAuthorities(prototype.getId()));
            return new UaaUser(prototype.withAuthorities(authorities));
        }

        private String getAuthorities(final String userId) {
            Set<String> authorities = new HashSet<>();
            getAuthorities(authorities, Collections.singletonList(userId));
            authorities.addAll(identityZoneManager.getCurrentIdentityZone().getConfig().getUserConfig().getDefaultGroups());
            return StringUtils.collectionToCommaDelimitedString(new HashSet<>(authorities));
        }

        protected void getAuthorities(Set<String> authorities, final List<String> memberIdList) {
            List<Map<String, Object>> results;
            if (memberIdList.isEmpty()) {
                return;
            }
            List<String> memberList = new ArrayList<>(memberIdList);
            results = executeAuthoritiesQuery(memberList);

            List<String> newMemberIdList = new ArrayList<>();
            for (Map<String, Object> resultItem : results) {
                String displayName = (String) resultItem.get("displayName");
                String groupId = (String) resultItem.get("id");
                if (!authorities.contains(displayName)) {
                    authorities.add(displayName);
                    newMemberIdList.add(groupId);
                }
            }
            getAuthorities(authorities, newMemberIdList);
        }

        private List<Map<String,Object>> executeAuthoritiesQuery(List<String> memberList) {
            Vendor dbVendor = databaseUrlModifier.getDatabaseType();
            if (Vendor.postgresql.equals(dbVendor)) {
                return executeAuthoritiesQueryPostgresql(memberList);
            } else if (Vendor.hsqldb.equals(dbVendor)) {
                return executeAuthoritiesQueryHSQL(memberList);
            } else {
                return executeAuthoritiesQueryDefault(memberList);
            }
        }

        private List<Map<String, Object>> executeAuthoritiesQueryDefault(List<String> memberList) {
            List<Map<String,Object>> results = new ArrayList<>();
            while (!memberList.isEmpty()) {
                StringBuilder dynamicAuthoritiesQuery = new StringBuilder("select g.id,g.displayName from groups g, group_membership m where g.id = m.group_id  and g.identity_zone_id=? and m.member_id in (");
                int size = maxSqlParameters > 1 ? Math.min(maxSqlParameters - 1, memberList.size()) : memberList.size();
                for (int i = 0; i < size - 1; i++) {
                    dynamicAuthoritiesQuery.append("?,");
                }
                dynamicAuthoritiesQuery.append("?);");

                Object[] parameterList = ArrayUtils.addAll(new Object[] { identityZoneManager.getCurrentIdentityZoneId() }, memberList.subList(0, size).toArray());

                results.addAll(jdbcTemplate.queryForList(dynamicAuthoritiesQuery.toString(), parameterList));
                memberList = memberList.subList(size, memberList.size());
            }
            return results;
        }

        private List<Map<String, Object>> executeAuthoritiesQueryPostgresql(List<String> memberList) {
            String arrayAuthoritiesQuery = "select g.id,g.displayName from groups g, group_membership m where g.id = m.group_id  and g.identity_zone_id=? and m.member_id = ANY(?)";
            Object[] parameterList = new Object[] { identityZoneManager.getCurrentIdentityZoneId() , memberList.toArray(new String[0])};
            return jdbcTemplate.queryForList(arrayAuthoritiesQuery, parameterList);
        }

        private List<Map<String, Object>> executeAuthoritiesQueryHSQL(List<String> memberList) {
            String arrayAuthoritiesQuery = "select g.id,g.displayName from groups g, group_membership m where g.id = m.group_id  and g.identity_zone_id=? and m.member_id IN (UNNEST(?))";
            Object[] parameterList = new Object[] { identityZoneManager.getCurrentIdentityZoneId() , memberList.toArray(new String[0])};
            return jdbcTemplate.queryForList(arrayAuthoritiesQuery, parameterList);
        }
    }


}
