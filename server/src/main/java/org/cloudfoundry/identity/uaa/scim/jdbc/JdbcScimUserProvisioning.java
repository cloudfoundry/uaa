/*******************************************************************************
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.resources.jdbc.AbstractQueryable;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Name;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConstraintFailedException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

import static java.sql.Types.VARCHAR;
import static org.springframework.util.StringUtils.hasText;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class JdbcScimUserProvisioning extends AbstractQueryable<ScimUser>
    implements ScimUserProvisioning, ResourceMonitor<ScimUser>, SystemDeletable {

    private final Log logger = LogFactory.getLog(getClass());

    @Override
    public Log getLogger() {
        return logger;
    }

    public static final String USER_FIELDS = "id,version,created,lastModified,username,email,givenName,familyName,active,phoneNumber,verified,origin,external_id,identity_zone_id,salt,passwd_lastmodified ";

    public static final String CREATE_USER_SQL = "insert into users (" + USER_FIELDS
                    + ",password) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    public static final String UPDATE_USER_SQL = "update users set version=?, lastModified=?, userName=?, email=?, givenName=?, familyName=?, active=?, phoneNumber=?, verified=?, origin=?, external_id=?, salt=? where id=? and version=? and identity_zone_id=?";

    public static final String DEACTIVATE_USER_SQL = "update users set active=? where id=? and identity_zone_id=?";

    public static final String VERIFY_USER_SQL = "update users set verified=? where id=? and identity_zone_id=?";

    public static final String DELETE_USER_SQL = "delete from users where id=? and identity_zone_id=?";

    public static final String CHANGE_PASSWORD_SQL = "update users set lastModified=?, password=?, passwd_lastmodified=? where id=? and identity_zone_id=?";

    public static final String READ_PASSWORD_SQL = "select password from users where id=? and identity_zone_id=?";

    public static final String USER_BY_ID_QUERY = "select " + USER_FIELDS + " from users " + "where id=? and identity_zone_id=?";

    public static final String ALL_USERS = "select " + USER_FIELDS + " from users";

    public static final String HARD_DELETE_OF_GROUP_MEMBERS_BY_ZONE = "delete from group_membership where member_type='USER' and member_id in (select id from users where identity_zone_id = ?)";

    public static final String HARD_DELETE_OF_GROUP_MEMBERS_BY_PROVIDER = "delete from group_membership where member_type='USER' and member_id in (select id from users where identity_zone_id = ? and origin = ?)";

    public static final String HARD_DELETE_OF_USER_APPROVALS_BY_ZONE = "delete from authz_approvals where user_id in (select id from users where identity_zone_id = ?)";

    public static final String HARD_DELETE_OF_USER_APPROVALS_BY_PROVIDER = "delete from authz_approvals where user_id in (select id from users where identity_zone_id = ? and origin = ?)";

    public static final String HARD_DELETE_BY_ZONE = "delete from users where identity_zone_id = ?";

    public static final String HARD_DELETE_BY_PROVIDER = "delete from users where identity_zone_id = ? and origin = ?";

    protected final JdbcTemplate jdbcTemplate;

    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private boolean deactivateOnDelete = true;

    private static final RowMapper<ScimUser> mapper = new ScimUserRowMapper();

    private Pattern usernamePattern = Pattern.compile("[\\p{L}+0-9+\\-_.@'!]+");

    public JdbcScimUserProvisioning(JdbcTemplate jdbcTemplate, JdbcPagingListFactory pagingListFactory) {
        super(jdbcTemplate, pagingListFactory, mapper);
        Assert.notNull(jdbcTemplate);
        this.jdbcTemplate = jdbcTemplate;
        setQueryConverter(new ScimSearchQueryConverter());
    }

    @Override
    public ScimUser retrieve(String id) {
        try {
            ScimUser u = jdbcTemplate.queryForObject(USER_BY_ID_QUERY, mapper, id, IdentityZoneHolder.get().getId());
            return u;
        } catch (EmptyResultDataAccessException e) {
            throw new ScimResourceNotFoundException("User " + id + " does not exist");
        }
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
    public List<ScimUser> retrieveAll() {
        return query("id pr", "created", true);
    }

    @Override
    public List<ScimUser> query(String filter, String sortBy, boolean ascending) {
        //validate syntax
        getQueryConverter().convert(filter, sortBy, ascending);

        if (hasText(filter)) {
            filter = "("+ filter+ ") and";
        }
        filter += " identity_zone_id eq \""+IdentityZoneHolder.get().getId()+"\"";
        return super.query(filter, sortBy, ascending);
    }

    @Override
    public ScimUser create(final ScimUser user) {
        if (!hasText(user.getOrigin())) {
            user.setOrigin(OriginKeys.UAA);
        }
        validate(user);
        logger.debug("Creating new user: " + user.getUserName());

        final String id = UUID.randomUUID().toString();
        final String identityZoneId = IdentityZoneHolder.get().getId();
        final String origin = user.getOrigin();

        try {
            jdbcTemplate.update(CREATE_USER_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    Timestamp t = new Timestamp(new Date().getTime());
                    ps.setString(1, id);
                    ps.setInt(2, user.getVersion());
                    ps.setTimestamp(3, t);
                    ps.setTimestamp(4, t);
                    ps.setString(5, user.getUserName());
                    ps.setString(6, user.getPrimaryEmail());
                    if (user.getName() == null) {
                        ps.setString(7, null);
                        ps.setString(8, null);
                    }
                    else {
                        ps.setString(7, user.getName().getGivenName());
                        ps.setString(8, user.getName().getFamilyName());
                    }
                    ps.setBoolean(9, user.isActive());
                    String phoneNumber = extractPhoneNumber(user);
                    ps.setString(10, phoneNumber);
                    ps.setBoolean(11, user.isVerified());
                    ps.setString(12, origin);
                    ps.setString(13, hasText(user.getExternalId())?user.getExternalId():null);
                    ps.setString(14, identityZoneId);
                    ps.setString(15, user.getSalt());

                    ps.setTimestamp(16, getPasswordLastModifiedTimestamp(t));
                    ps.setString(17, user.getPassword());
                }

            });
        } catch (DuplicateKeyException e) {
            ScimUser existingUser = query("userName eq \"" + user.getUserName() + "\" and origin eq \"" + (hasText(user.getOrigin())? user.getOrigin() : OriginKeys.UAA) + "\"").get(0);
            Map<String,Object> userDetails = new HashMap<>();
            userDetails.put("active", existingUser.isActive());
            userDetails.put("verified", existingUser.isVerified());
            userDetails.put("user_id", existingUser.getId());
            throw new ScimResourceAlreadyExistsException("Username already in use: " + existingUser.getUserName(), userDetails);
        }
        return retrieve(id);
    }

    protected Timestamp getPasswordLastModifiedTimestamp(Timestamp t) {
        Calendar cal = new GregorianCalendar();
        cal.set(Calendar.MILLISECOND, 0);
        return new Timestamp(cal.getTimeInMillis());
    }

    @Override
    public ScimUser createUser(ScimUser user, final String password) throws InvalidPasswordException,
                    InvalidScimResourceException {
        user.setPassword(passwordEncoder.encode(password));
        return create(user);
    }

    protected void validate(final ScimUser user) throws InvalidScimResourceException {
        if (!hasText(user.getUserName())) {
            throw new InvalidScimResourceException("A username must be provided.");
        }
        if (OriginKeys.UAA.equals(user.getOrigin()) && !usernamePattern.matcher(user.getUserName()).matches()) {
            throw new InvalidScimResourceException("Username must match pattern: " + usernamePattern.pattern());
        }
        if (user.getEmails() == null || user.getEmails().size() != 1) {
            throw new InvalidScimResourceException("Exactly one email must be provided.");
        }
        for (ScimUser.Email email : user.getEmails()) {
            if (email == null || email.getValue() == null || email.getValue().isEmpty()) {
                throw new InvalidScimResourceException("An email must be provided.");
            }
        }
    }

    private String extractPhoneNumber(final ScimUser user) {
        String phoneNumber = null;
        if (user.getPhoneNumbers() != null && !user.getPhoneNumbers().isEmpty()) {
            phoneNumber = user.getPhoneNumbers().get(0).getValue();
        }
        return phoneNumber;
    }

    @Override
    public ScimUser update(final String id, final ScimUser user) throws InvalidScimResourceException {
        validate(user);
        logger.debug("Updating user " + user.getUserName());
        final String origin = hasText(user.getOrigin()) ? user.getOrigin() : OriginKeys.UAA;
        final String zoneId = IdentityZoneHolder.get().getId();
        int updated = jdbcTemplate.update(UPDATE_USER_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                int pos = 1;
                Timestamp t = new Timestamp(new Date().getTime());
                ps.setInt(pos++, user.getVersion() + 1);
                ps.setTimestamp(pos++, t);
                ps.setString(pos++, user.getUserName());
                ps.setString(pos++, user.getPrimaryEmail());
                ps.setString(pos++, user.getName().getGivenName());
                ps.setString(pos++, user.getName().getFamilyName());
                ps.setBoolean(pos++, user.isActive());
                ps.setString(pos++, extractPhoneNumber(user));
                ps.setBoolean(pos++, user.isVerified());
                ps.setString(pos++, origin);
                ps.setString(pos++, hasText(user.getExternalId())?user.getExternalId():null);
                ps.setString(pos++, user.getSalt());
                ps.setString(pos++, id);
                ps.setInt(pos++, user.getVersion());
                ps.setString(pos++, zoneId);
            }
        });
        ScimUser result = retrieve(id);
        if (updated == 0) {
            throw new OptimisticLockingFailureException(String.format(
                            "Attempt to update a user (%s) with wrong version: expected=%d but found=%d", id,
                            result.getVersion(), user.getVersion()));
        }
        if (updated > 1) {
            throw new IncorrectResultSizeDataAccessException(1);
        }
        return result;
    }

    @Override
    public void changePassword(final String id, String oldPassword, final String newPassword)
                    throws ScimResourceNotFoundException {
        if (oldPassword != null && !checkPasswordMatches(id, oldPassword)) {
            throw new BadCredentialsException("Old password is incorrect");
        }
        if (checkPasswordMatches(id, newPassword)) {
            return; //we don't want to update the same password
        }
        final String encNewPassword = passwordEncoder.encode(newPassword);
        final String zoneId = IdentityZoneHolder.get().getId();
        int updated = jdbcTemplate.update(CHANGE_PASSWORD_SQL, new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                Timestamp t = new Timestamp(System.currentTimeMillis());
                ps.setTimestamp(1, t);
                ps.setString(2, encNewPassword);
                ps.setTimestamp(3, getPasswordLastModifiedTimestamp(t));
                ps.setString(4, id);
                ps.setString(5, zoneId);
            }
        });
        if (updated == 0) {
            throw new ScimResourceNotFoundException("User " + id + " does not exist");
        }
        if (updated != 1) {
            throw new ScimResourceConstraintFailedException("User " + id + " duplicated");
        }
    }

    // Checks the existing password for a user
    public boolean checkPasswordMatches(String id, String password) {
        String currentPassword;
        try {
            currentPassword =
                jdbcTemplate.queryForObject(
                    READ_PASSWORD_SQL,
                    new Object[] { id, IdentityZoneHolder.get().getId() },
                    new int[] { VARCHAR, VARCHAR },
                    String.class
                );
        } catch (IncorrectResultSizeDataAccessException e) {
            throw new ScimResourceNotFoundException("User " + id + " does not exist");
        }

        return passwordEncoder.matches(password, currentPassword);
    }

    @Override
    public ScimUser delete(String id, int version) {
        ScimUser user = retrieve(id);
        return deactivateOnDelete ? deactivateUser(user, version) : deleteUser(user, version);
    }

    private ScimUser deactivateUser(ScimUser user, int version) {
        logger.debug("Deactivating user: " + user.getId());
        int updated;
        if (version < 0) {
            // Ignore
            updated = jdbcTemplate.update(DEACTIVATE_USER_SQL, false, user.getId(), IdentityZoneHolder.get().getId());
        } else {
            updated = jdbcTemplate.update(DEACTIVATE_USER_SQL + " and version=?", false, user.getId(), IdentityZoneHolder.get().getId(), version);
        }
        if (updated == 0) {
            throw new OptimisticLockingFailureException(String.format(
                            "Attempt to update a user (%s) with wrong version: expected=%d but found=%d", user.getId(),
                            user.getVersion(), version));
        }
        if (updated > 1) {
            throw new IncorrectResultSizeDataAccessException(1);
        }
        user.setActive(false);
        return user;
    }

    @Override
    public ScimUser verifyUser(String id, int version) throws ScimResourceNotFoundException,
                    InvalidScimResourceException {
        logger.debug("Verifying user: " + id);
        int updated;
        if (version < 0) {
            // Ignore
            updated = jdbcTemplate.update(VERIFY_USER_SQL, true, id, IdentityZoneHolder.get().getId());
        }
        else {
            updated = jdbcTemplate.update(VERIFY_USER_SQL + " and version=?", true, id, IdentityZoneHolder.get().getId(), version);
        }
        ScimUser user = retrieve(id);
        if (updated == 0) {
            throw new OptimisticLockingFailureException(String.format(
                            "Attempt to update a user (%s) with wrong version: expected=%d but found=%d", user.getId(),
                            user.getVersion(), version));
        }
        if (updated > 1) {
            throw new IncorrectResultSizeDataAccessException(1);
        }
        return user;
    }

    private ScimUser deleteUser(ScimUser user, int version) {
        logger.debug("Deleting user: " + user.getId());
        int updated;

        if (version < 0) {
            updated = jdbcTemplate.update(DELETE_USER_SQL, user.getId(), IdentityZoneHolder.get().getId());
        }
        else {
            updated = jdbcTemplate.update(DELETE_USER_SQL + " and version=?", user.getId(), IdentityZoneHolder.get().getId(), version);
        }
        if (updated == 0) {
            throw new OptimisticLockingFailureException(String.format(
                            "Attempt to update a user (%s) with wrong version: expected=%d but found=%d", user.getId(),
                            user.getVersion(), version));
        }
        return user;
    }

    public void setDeactivateOnDelete(boolean deactivateOnDelete) {
        this.deactivateOnDelete = deactivateOnDelete;
    }

    /**
     * The encoder used to hash passwords before storing them in the database.
     *
     * Defaults to a {@link BCryptPasswordEncoder}.
     */
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Sets the regular expression which will be used to validate the username.
     */
    public void setUsernamePattern(String usernamePattern) {
        Assert.hasText(usernamePattern, "Username pattern must not be empty");
        this.usernamePattern = Pattern.compile(usernamePattern);
    }

    public int deleteByIdentityZone(String zoneId) {
        jdbcTemplate.update(HARD_DELETE_OF_GROUP_MEMBERS_BY_ZONE, zoneId);
        jdbcTemplate.update(HARD_DELETE_OF_USER_APPROVALS_BY_ZONE, zoneId);
        return jdbcTemplate.update(HARD_DELETE_BY_ZONE, zoneId);
    }

    public int deleteByOrigin(String origin, String zoneId) {
        jdbcTemplate.update(HARD_DELETE_OF_GROUP_MEMBERS_BY_PROVIDER, zoneId, origin);
        jdbcTemplate.update(HARD_DELETE_OF_USER_APPROVALS_BY_PROVIDER, zoneId, origin);
        return jdbcTemplate.update(HARD_DELETE_BY_PROVIDER, zoneId, origin);
    }

    private static final class ScimUserRowMapper implements RowMapper<ScimUser> {
        @Override
        public ScimUser mapRow(ResultSet rs, int rowNum) throws SQLException {
            String id = rs.getString(1);
            int version = rs.getInt(2);
            Date created = rs.getTimestamp(3);
            Date lastModified = rs.getTimestamp(4);
            String userName = rs.getString(5);
            String email = rs.getString(6);
            String givenName = rs.getString(7);
            String familyName = rs.getString(8);
            boolean active = rs.getBoolean(9);
            String phoneNumber = rs.getString(10);
            boolean verified = rs.getBoolean(11);
            String origin = rs.getString(12);
            String externalId = rs.getString(13);
            String zoneId = rs.getString(14);
            String salt = rs.getString(15);
            Date passwordLastModified = rs.getTimestamp(16);
            ScimUser user = new ScimUser();
            user.setId(id);
            ScimMeta meta = new ScimMeta();
            meta.setVersion(version);
            meta.setCreated(created);
            meta.setLastModified(lastModified);
            user.setMeta(meta);
            user.setUserName(userName);
            if (hasText(email)) { user.addEmail(email); }
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
            user.setSalt(salt);
            user.setPasswordLastModified(passwordLastModified);
            return user;
        }
    }

    @Override
    public int getTotalCount() {
        Integer count = jdbcTemplate.queryForObject("select count(*) from users",Integer.class);
        if (count == null) {
            return 0;
        }
        return count;
    }

    @Override
    protected void validateOrderBy(String orderBy) throws IllegalArgumentException {
        super.validateOrderBy(orderBy, USER_FIELDS);
    }
}
