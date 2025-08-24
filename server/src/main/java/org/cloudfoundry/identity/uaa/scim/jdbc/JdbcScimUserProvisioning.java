/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.logging.LogSanitizerUtil;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.resources.jdbc.AbstractQueryable;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.SearchQueryConverter;
import org.cloudfoundry.identity.uaa.resources.jdbc.SearchQueryConverter.ProcessedFilter;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Name;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConstraintFailedException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.util.ScimUtils;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.sql.Types.VARCHAR;
import static java.util.stream.Collectors.joining;
import static org.springframework.util.StringUtils.hasText;

@Component("scimUserProvisioning")
public class JdbcScimUserProvisioning extends AbstractQueryable<ScimUser>
        implements ScimUserProvisioning, ResourceMonitor<ScimUser>, SystemDeletable {

    private static final String ATTEMPT_UPDATE_ERROR_MESSAGE = "Attempt to update a user (%s) with wrong version: expected=%d but found=%d";
    private static final String USER_DOES_NOT_EXIST_MESSAGE = "User %s does not exist";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public Logger getLogger() {
        return logger;
    }

    public static final String USER_FIELDS = "id,version,created,lastModified,username,email,givenName,familyName,active,phoneNumber,verified,origin,external_id,identity_zone_id,alias_id,alias_zid,salt,passwd_lastmodified,last_logon_success_time,previous_logon_success_time";

    public static final String CREATE_USER_SQL = "insert into users (" + USER_FIELDS
            + ",password) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    public static final String UPDATE_USER_SQL = "update users set version=?, lastModified=?, username=?, email=?, givenName=?, familyName=?, active=?, phoneNumber=?, verified=?, origin=?, external_id=?, salt=?, alias_id=?, alias_zid=? where id=? and version=? and identity_zone_id=?";

    public static final String DEACTIVATE_USER_SQL = "update users set active=? where id=? and identity_zone_id=?";

    public static final String VERIFY_USER_SQL = "update users set verified=? where id=? and identity_zone_id=?";

    public static final String DELETE_USER_SQL = "delete from users where id=? and identity_zone_id=?";

    public static final String CHANGE_PASSWORD_SQL = "update users set lastModified=?, password=?, passwd_lastmodified=? where id=? and identity_zone_id=?";

    public static final String READ_PASSWORD_SQL = "select password from users where id=? and identity_zone_id=?";

    public static final String UPDATE_PASSWORD_CHANGE_REQUIRED_SQL = "update users set passwd_change_required=? where id=? and identity_zone_id=?";

    public static final String UPDATE_LAST_LOGON_TIME_SQL = JdbcUaaUserDatabase.DEFAULT_UPDATE_USER_LAST_LOGON;

    public static final String READ_PASSWORD_CHANGE_REQUIRED_SQL = "select passwd_change_required from users where id=? and identity_zone_id=?";

    public static final String USER_BY_ID_QUERY = "select " + USER_FIELDS + " from users " + "where id=? and identity_zone_id=?";

    public static final String USER_BY_EMAIL_AND_ORIGIN_AND_ZONE_QUERY = "select " + USER_FIELDS + " from users " + "where LOWER(email)=LOWER(?) and LOWER(origin)=LOWER(?) and LOWER(identity_zone_id)=LOWER(?)";

    public static final String USER_BY_USERNAME_AND_ZONE_QUERY = "select " + USER_FIELDS + " from users " + "where LOWER(username)=LOWER(?) and LOWER(identity_zone_id)=LOWER(?)";

    public static final String USER_BY_USERNAME_AND_ORIGIN_AND_ZONE_QUERY = "select " + USER_FIELDS + " from users " + "where LOWER(username)=LOWER(?) and LOWER(origin)=LOWER(?) and LOWER(identity_zone_id)=LOWER(?)";

    public static final String ALL_USERS = "select " + USER_FIELDS + " from users";

    public static final String HARD_DELETE_OF_GROUP_MEMBERS_BY_ZONE = "delete from group_membership where identity_zone_id = ?";

    public static final String HARD_DELETE_OF_GROUP_MEMBERS_BY_PROVIDER = "delete from group_membership where identity_zone_id = ? and origin = ?";

    public static final String HARD_DELETE_BY_ZONE = "delete from users where identity_zone_id = ?";

    public static final String HARD_DELETE_BY_PROVIDER = "delete from users where identity_zone_id = ? and origin = ?";

    public static final String USER_COUNT_BY_ZONE = "select count(*) from users where identity_zone_id = ?";

    protected final JdbcTemplate jdbcTemplate;

    private final PasswordEncoder passwordEncoder;

    private final boolean deactivateOnDelete;

    private static final RowMapper<ScimUser> mapper = new ScimUserRowMapper();

    private final TimeService timeService;

    private final JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning;
    private final IdentityZoneManager identityZoneManager;
    private final SearchQueryConverter joinConverter;

    public JdbcScimUserProvisioning(
            final NamedParameterJdbcTemplate namedJdbcTemplate,
            @Qualifier("jdbcPagingListFactory") final JdbcPagingListFactory pagingListFactory,
            @Qualifier("nonCachingPasswordEncoder") final PasswordEncoder passwordEncoder,
            final IdentityZoneManager identityZoneManager,
            final JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning,
            @Qualifier("scimUserQueryConverter") final SearchQueryConverter queryConverter,
            @Qualifier("scimJoinQueryConverter") final SearchQueryConverter joinConverter,
            final TimeService timeService,
            @Value("${scim.delete.deactivate:false}") final boolean deactivateOnDelete
    ) {
        super(namedJdbcTemplate, pagingListFactory, mapper);
        Assert.notNull(namedJdbcTemplate, "JdbcTemplate required");
        this.jdbcTemplate = namedJdbcTemplate.getJdbcTemplate();
        setQueryConverter(queryConverter);
        this.passwordEncoder = passwordEncoder;
        this.jdbcIdentityZoneProvisioning = jdbcIdentityZoneProvisioning;
        this.identityZoneManager = identityZoneManager;
        this.joinConverter = joinConverter;
        this.timeService = timeService;
        this.deactivateOnDelete = deactivateOnDelete;
    }

    @Override
    public ScimUser retrieve(String id, String zoneId) {
        try {
            return jdbcTemplate.queryForObject(USER_BY_ID_QUERY, mapper, id, zoneId);
        } catch (EmptyResultDataAccessException e) {
            throw new ScimResourceNotFoundException(USER_DOES_NOT_EXIST_MESSAGE.formatted(id));
        }
    }

    @Override
    public List<ScimUser> retrieveByEmailAndZone(String email, String origin, String zoneId) {
        return jdbcTemplate.query(USER_BY_EMAIL_AND_ORIGIN_AND_ZONE_QUERY, mapper, email, origin, zoneId);
    }

    @Override
    public List<ScimUser> retrieveByUsernameAndZone(String username, String zoneId) {
        return jdbcTemplate.query(USER_BY_USERNAME_AND_ZONE_QUERY, mapper, username, zoneId);
    }

    @Override
    public List<ScimUser> retrieveByScimFilterOnlyActive(
            final String filter,
            final String sortBy,
            final boolean ascending,
            final String zoneId
    ) {
        validateOrderBy(sortBy);
        /* since the two tables used in the query ('users' and 'identity_provider') have columns with identical names,
         * we must ensure that the columns of 'users' are used in the WHERE clause generated for the SCIM filter */
        String joinName = joinConverter.getJoinName();

        // build WHERE clause
        final ProcessedFilter where = joinConverter.convert(filter, sortBy, ascending, zoneId);
        final String whereClauseScimFilter = where.getSql();
        String whereClause = "idp.active is true and (";
        if (where.hasOrderBy()) {
            whereClause += whereClauseScimFilter.replace(ProcessedFilter.ORDER_BY, ")" + ProcessedFilter.ORDER_BY);
        } else {
            whereClause += whereClauseScimFilter + ")";
        }

        final String userFieldsWithPrefix = Arrays.stream(USER_FIELDS.split(","))
                .map(field -> joinName + "." + field)
                .collect(joining(", "));
        String joinStatement = "%s join identity_provider idp on %s.origin = idp.origin_key and %s.identity_zone_id = idp.identity_zone_id".formatted(joinName, joinName, joinName);
        final String sql = "select %s from users %s where %s".formatted(
                userFieldsWithPrefix,
                joinStatement,
                whereClause
        );

        if (getPageSize() > 0 && getPageSize() < Integer.MAX_VALUE) {
            return pagingListFactory.createJdbcPagingList(sql, where.getParams(), rowMapper, getPageSize());
        }

        return namedParameterJdbcTemplate.query(sql, where.getParams(), rowMapper);
    }

    @Override
    public List<ScimUser> retrieveByUsernameAndOriginAndZone(String username, String origin, String zoneId) {
        return jdbcTemplate.query(USER_BY_USERNAME_AND_ORIGIN_AND_ZONE_QUERY, mapper, username, origin, zoneId);
    }

    @Override
    protected String getBaseSqlQuery() {
        return ALL_USERS;
    }

    @Override
    protected String getTableName() {
        return "users";
    }

    @Override
    public List<ScimUser> retrieveAll(String zoneId) {
        return query("id pr", "created", true, zoneId);
    }

    @Override
    public ScimUser create(final ScimUser user, String zoneId) {
        UserConfig userConfig = getUserConfig(zoneId);
        validateUserLimit(zoneId, userConfig);
        if (!hasText(user.getOrigin())) {
            user.setOrigin(OriginKeys.UAA);
        }
        if (isCheckOriginEnabled(userConfig)) {
            checkOrigin(user.getOrigin(), zoneId);
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Creating new user: {}", UaaStringUtils.getCleanedUserControlString(user.getUserName()));
        }

        final String id = UUID.randomUUID().toString();
        final String identityZoneId = zoneId;
        final String origin = user.getOrigin();

        try {
            jdbcTemplate.update(CREATE_USER_SQL, ps -> {
                Timestamp t = new Timestamp(new Date().getTime());
                ps.setString(1, id);
                ps.setInt(2, user.getVersion());
                ps.setTimestamp(3, t); // created
                ps.setTimestamp(4, t); // lastModified
                ps.setString(5, user.getUserName());
                ps.setString(6, user.getPrimaryEmail());
                if (user.getName() == null) {
                    ps.setString(7, null); // givenName
                    ps.setString(8, null); // familyName
                } else {
                    ps.setString(7, user.getName().getGivenName());
                    ps.setString(8, user.getName().getFamilyName());
                }
                ps.setBoolean(9, user.isActive());
                String phoneNumber = extractPhoneNumber(user);
                ps.setString(10, phoneNumber);
                ps.setBoolean(11, user.isVerified());
                ps.setString(12, origin);
                ps.setString(13, hasText(user.getExternalId()) ? user.getExternalId() : null);
                ps.setString(14, identityZoneId);
                ps.setString(15, hasText(user.getAliasId()) ? user.getAliasId() : null);
                ps.setString(16, hasText(user.getAliasZid()) ? user.getAliasZid() : null);
                ps.setString(17, user.getSalt());

                ps.setTimestamp(18, getPasswordLastModifiedTimestamp(t));
                ps.setNull(19, Types.BIGINT); // last_logon_success_time
                ps.setNull(20, Types.BIGINT); // previous_logon_success_time
                ps.setString(21, user.getPassword());
            });
        } catch (DuplicateKeyException e) {
            String userOrigin = hasText(user.getOrigin()) ? user.getOrigin() : OriginKeys.UAA;
            Map<String, Object> userDetails = Collections.singletonMap("origin", userOrigin);
            throw new ScimResourceAlreadyExistsException("Username already in use: " + user.getUserName(), userDetails);
        }
        return retrieve(id, zoneId);
    }

    protected Timestamp getPasswordLastModifiedTimestamp(Timestamp t) {
        Calendar cal = new GregorianCalendar();
        cal.set(Calendar.MILLISECOND, 0);
        return new Timestamp(cal.getTimeInMillis());
    }

    @Override
    public ScimUser createUser(ScimUser user, final String password, String zoneId) throws InvalidPasswordException,
            InvalidScimResourceException {
        user.setPassword(passwordEncoder.encode(password));
        return create(user, zoneId);
    }

    public String extractPhoneNumber(final ScimUser user) {
        String phoneNumber = null;
        if (user.getPhoneNumbers() != null && !user.getPhoneNumbers().isEmpty()) {
            phoneNumber = user.getPhoneNumbers().getFirst().getValue();
        }
        return phoneNumber;
    }

    @Override
    public ScimUser update(final String id, final ScimUser user, final String zoneId) throws InvalidScimResourceException {
        if (logger.isDebugEnabled()) {
            logger.debug("Updating user {}", user.getUserName());
        }
        final String origin = hasText(user.getOrigin()) ? user.getOrigin() : OriginKeys.UAA;
        user.setOrigin(origin);

        // check if the origin was changed
        final ScimUser existingUser = retrieve(id, zoneId);
        if (!origin.equals(existingUser.getOrigin())) {
            throw new InvalidScimResourceException("Cannot change user's origin in update operation.");
        }

        ScimUtils.validate(user);
        int updated = jdbcTemplate.update(UPDATE_USER_SQL, ps -> {
            int pos = 1;
            Timestamp t = new Timestamp(new Date().getTime());

            // placeholders in UPDATE
            ps.setInt(pos++, user.getVersion() + 1);
            ps.setTimestamp(pos++, t); // lastModified
            ps.setString(pos++, user.getUserName());
            ps.setString(pos++, user.getPrimaryEmail());
            ps.setString(pos++, user.getName().getGivenName());
            ps.setString(pos++, user.getName().getFamilyName());
            ps.setBoolean(pos++, user.isActive());
            ps.setString(pos++, extractPhoneNumber(user));
            ps.setBoolean(pos++, user.isVerified());
            ps.setString(pos++, origin);
            ps.setString(pos++, hasText(user.getExternalId()) ? user.getExternalId() : null);
            ps.setString(pos++, user.getSalt());
            ps.setString(pos++, user.getAliasId());
            ps.setString(pos++, user.getAliasZid());

            // placeholders in WHERE
            ps.setString(pos++, id);
            ps.setInt(pos++, user.getVersion());
            ps.setString(pos, zoneId);
        });
        ScimUser result = retrieve(id, zoneId);
        if (updated == 0) {
            throw new OptimisticLockingFailureException(ATTEMPT_UPDATE_ERROR_MESSAGE.formatted(id,
                    result.getVersion(), user.getVersion()));
        }
        if (updated > 1) {
            throw new IncorrectResultSizeDataAccessException(1);
        }
        return result;
    }

    @Override
    public void changePassword(final String id, String oldPassword, final String newPassword, String zoneId)
            throws ScimResourceNotFoundException {
        if (oldPassword != null && !checkPasswordMatches(id, oldPassword, zoneId)) {
            throw new BadCredentialsException("Old password is incorrect");
        }
        if (checkPasswordMatches(id, newPassword, zoneId)) {
            return; //we don't want to update the same password
        }
        final String encNewPassword = passwordEncoder.encode(newPassword);
        int updated = jdbcTemplate.update(CHANGE_PASSWORD_SQL, ps -> {
            Timestamp t = new Timestamp(System.currentTimeMillis());
            ps.setTimestamp(1, t);
            ps.setString(2, encNewPassword);
            ps.setTimestamp(3, getPasswordLastModifiedTimestamp(t));
            ps.setString(4, id);
            ps.setString(5, zoneId);
        });
        if (updated == 0) {
            throw new ScimResourceNotFoundException(USER_DOES_NOT_EXIST_MESSAGE.formatted(id));
        }
        if (updated != 1) {
            throw new ScimResourceConstraintFailedException("User " + id + " duplicated");
        }
    }

    // Checks the existing password for a user
    public boolean checkPasswordMatches(String id, CharSequence password, String zoneId) {
        String currentPassword;
        try {
            currentPassword =
                    jdbcTemplate.queryForObject(
                            READ_PASSWORD_SQL,
                            new Object[]{id, zoneId},
                            new int[]{VARCHAR, VARCHAR},
                            String.class
                    );
        } catch (IncorrectResultSizeDataAccessException e) {
            throw new ScimResourceNotFoundException(USER_DOES_NOT_EXIST_MESSAGE.formatted(id));
        }

        return passwordEncoder.matches(password, currentPassword);
    }

    @Override
    public boolean checkPasswordChangeIndividuallyRequired(String userId, String zoneId) throws ScimResourceNotFoundException {
        return jdbcTemplate.queryForObject(READ_PASSWORD_CHANGE_REQUIRED_SQL, boolean.class, userId, zoneId);
    }

    @Override
    public void updatePasswordChangeRequired(String userId, boolean passwordChangeRequired, String zoneId) throws ScimResourceNotFoundException {
        int updated = jdbcTemplate.update(UPDATE_PASSWORD_CHANGE_REQUIRED_SQL, ps -> {
            ps.setBoolean(1, passwordChangeRequired);
            ps.setString(2, userId);
            ps.setString(3, zoneId);
        });
        if (updated == 0) {
            throw new ScimResourceNotFoundException(USER_DOES_NOT_EXIST_MESSAGE.formatted(userId));
        }
    }

    @Override
    public ScimUser delete(String id, int version, String zoneId) {
        ScimUser user = retrieve(id, zoneId);
        return deactivateOnDelete ? deactivateUser(user, version, zoneId) : deleteUser(user, version, zoneId);
    }

    private ScimUser deactivateUser(ScimUser user, int version, String zoneId) {
        if (logger.isDebugEnabled()) {
            logger.debug("Deactivating user: {}", user.getId());
        }
        int updated;
        if (version < 0) {
            // Ignore
            updated = jdbcTemplate.update(DEACTIVATE_USER_SQL, false, user.getId(), zoneId);
        } else {
            updated = jdbcTemplate.update(DEACTIVATE_USER_SQL + " and version=?", false, user.getId(), zoneId, version);
        }
        if (updated == 0) {
            throw new OptimisticLockingFailureException(ATTEMPT_UPDATE_ERROR_MESSAGE.formatted(user.getId(),
                    user.getVersion(), version));
        }
        if (updated > 1) {
            throw new IncorrectResultSizeDataAccessException(1);
        }
        user.setActive(false);
        return user;
    }

    @Override
    public ScimUser verifyUser(String id, int version, String zoneId) throws ScimResourceNotFoundException,
            InvalidScimResourceException {
        if (logger.isDebugEnabled()) {
            logger.debug("Verifying user: {}", LogSanitizerUtil.sanitize(id));
        }
        int updated;
        if (version < 0) {
            // Ignore
            updated = jdbcTemplate.update(VERIFY_USER_SQL, true, id, zoneId);
        } else {
            updated = jdbcTemplate.update(VERIFY_USER_SQL + " and version=?", true, id, zoneId, version);
        }
        ScimUser user = retrieve(id, zoneId);
        if (updated == 0) {
            throw new OptimisticLockingFailureException(ATTEMPT_UPDATE_ERROR_MESSAGE.formatted(user.getId(),
                    user.getVersion(), version));
        }
        if (updated > 1) {
            throw new IncorrectResultSizeDataAccessException(1);
        }
        return user;
    }

    protected ScimUser deleteUser(ScimUser user, int version, String zoneId) {
        int updated = deleteUser(user.getId(), version, zoneId);
        if (updated == 0) {
            throw new OptimisticLockingFailureException(ATTEMPT_UPDATE_ERROR_MESSAGE.formatted(user.getId(),
                    version, version));
        }
        return user;
    }

    protected int deleteUser(String userId, int version, String zoneId) {
        if (logger.isDebugEnabled()) {
            logger.debug("Deleting user: {}", userId);
        }
        int updated;

        if (version < 0) {
            updated = jdbcTemplate.update(DELETE_USER_SQL, userId, zoneId);
        } else {
            updated = jdbcTemplate.update(DELETE_USER_SQL + " and version=?", userId, zoneId, version);
        }
        return updated;
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        jdbcTemplate.update(HARD_DELETE_OF_GROUP_MEMBERS_BY_ZONE, zoneId);
        return jdbcTemplate.update(HARD_DELETE_BY_ZONE, zoneId);
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        jdbcTemplate.update(HARD_DELETE_OF_GROUP_MEMBERS_BY_PROVIDER, zoneId, origin);
        return jdbcTemplate.update(HARD_DELETE_BY_PROVIDER, zoneId, origin);
    }

    @Override
    public int deleteByUser(String userId, String zoneId) {
        deleteUser(userId, -1, zoneId);
        return 1;
    }

    private static final class ScimUserRowMapper implements RowMapper<ScimUser> {
        @Override
        public ScimUser mapRow(ResultSet rs, int rowNum) throws SQLException {
            String id = rs.getString("id");
            int version = rs.getInt("version");
            Date created = rs.getTimestamp("created");
            Date lastModified = rs.getTimestamp("lastModified");
            String userName = rs.getString("username");
            String email = rs.getString("email");
            String givenName = rs.getString("givenName");
            String familyName = rs.getString("familyName");
            boolean active = rs.getBoolean("active");
            String phoneNumber = rs.getString("phoneNumber");
            boolean verified = rs.getBoolean("verified");
            String origin = rs.getString("origin");
            String externalId = rs.getString("external_id");
            String zoneId = rs.getString("identity_zone_id");
            String aliasId = rs.getString("alias_id");
            String aliasZid = rs.getString("alias_zid");
            String salt = rs.getString("salt");
            Date passwordLastModified = rs.getTimestamp("passwd_lastmodified");
            Long lastLogonTime = (Long) rs.getObject("last_logon_success_time");
            Long previousLogonTime = (Long) rs.getObject("previous_logon_success_time");
            ScimUser user = new ScimUser();
            user.setId(id);
            ScimMeta meta = new ScimMeta();
            meta.setVersion(version);
            meta.setCreated(created);
            meta.setLastModified(lastModified);
            user.setMeta(meta);
            user.setUserName(userName);
            if (hasText(email)) {
                user.addEmail(email);
            }
            if (phoneNumber != null) {
                user.addPhoneNumber(phoneNumber);
            }
            Name name = new Name();
            name.setGivenName(givenName);
            name.setFamilyName(familyName);
            user.setName(name);
            user.setActive(active);
            user.setVerified(verified);
            user.setOrigin(origin);
            user.setExternalId(externalId);
            user.setZoneId(zoneId);
            user.setAliasId(aliasId);
            user.setAliasZid(aliasZid);
            user.setSalt(salt);
            user.setPasswordLastModified(passwordLastModified);
            user.setLastLogonTime(lastLogonTime);
            user.setPreviousLogonTime(previousLogonTime);
            return user;
        }
    }

    @Override
    public int getTotalCount() {
        Integer count = jdbcTemplate.queryForObject("select count(*) from users", Integer.class);
        if (count == null) {
            return 0;
        }
        return count;
    }

    public int getUsersCountForZone(String zoneId) {
        Integer count = jdbcTemplate.queryForObject(USER_COUNT_BY_ZONE, Integer.class, zoneId);
        return count != null ? count : 0;
    }

    @Override
    protected void validateOrderBy(String orderBy) throws IllegalArgumentException {
        super.validateOrderBy(orderBy, USER_FIELDS.replace(",salt", ""));
    }

    @Override
    public void updateLastLogonTime(String id, String zoneId) {
        jdbcTemplate.update(UPDATE_LAST_LOGON_TIME_SQL, timeService.getCurrentTimeMillis(), id, zoneId);
    }

    private UserConfig getUserConfig(String zoneId) throws InvalidScimResourceException {
        try {
            IdentityZone currentZone = identityZoneManager.getCurrentIdentityZone();
            return currentZone.getId().equals(zoneId) ?
                    currentZone.getConfig().getUserConfig() :
                    jdbcIdentityZoneProvisioning.retrieve(zoneId).getConfig().getUserConfig();
        } catch (ZoneDoesNotExistsException e) {
            throw new InvalidScimResourceException("Invalid identity zone id: %s".formatted(zoneId));
        }
    }

    private void validateUserLimit(String zoneId, UserConfig userConfig) {
        // get the current limit of allowed users
        long maxAllowedUsers = userConfig == null ? -1 : userConfig.getMaxUsers();
        // check, if there is a limit (>0), that the limit is not reached with one user more (getUsersCountForZone + 1)
        if (maxAllowedUsers > 0 && maxAllowedUsers < (getUsersCountForZone(zoneId) + 1)) {
            throw new InvalidScimResourceException("The maximum allowed numbers of users: " + maxAllowedUsers
                    + " is reached already in Identity Zone " + zoneId);
        }
    }

    private boolean isCheckOriginEnabled(UserConfig userConfig) {
        return userConfig != null && userConfig.isCheckOriginEnabled();
    }

    private void checkOrigin(String origin, String zoneId) {
        Integer count = jdbcTemplate.queryForObject("select count(*) from identity_provider where origin_key=? and identity_zone_id=? ", Integer.class, origin, zoneId);
        if (count == null || count == 0) {
            throw new InvalidScimResourceException("Invalid origin " + origin + " in Identity Zone " + zoneId);
        }
    }
}
