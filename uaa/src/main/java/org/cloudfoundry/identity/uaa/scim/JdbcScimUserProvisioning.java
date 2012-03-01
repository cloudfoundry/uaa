/**
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.scim;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Meta;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Name;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class JdbcScimUserProvisioning implements ScimUserProvisioning {

	private final Log logger = LogFactory.getLog(getClass());

	public static final String USER_FIELDS = "id,version,created,lastModified,username,email,givenName,familyName,active";

	public static final String CREATE_USER_SQL = "insert into users (" + USER_FIELDS
			+ ",password) values (?,?,?,?,?,?,?,?,?,?)";

	public static final String UPDATE_USER_SQL = "update users set version=?, lastModified=?, email=?, givenName=?, familyName=?, active=? where id=? and version=?";

	public static final String DELETE_USER_SQL = "update users set active=false where id=? and version=?";

	public static final String ID_FOR_DELETED_USER_SQL = "select id from users where userName=? and active=false";

	public static final String CHANGE_PASSWORD_SQL = "update users set lastModified=?, password=? where id=?";

	public static final String READ_PASSWORD_SQL = "select password from users where id=?";

	public static final String USER_BY_ID_QUERY = "select " + USER_FIELDS + " from users " + "where id=?";

	public static final String ALL_USERS = "select " + USER_FIELDS + " from users";

	/*
	 * Filter regexes for turning SCIM filters into SQL:
	 */

	static final Pattern emailsValuePattern = Pattern.compile("emails\\.value", Pattern.CASE_INSENSITIVE);

	static final Pattern coPattern = Pattern.compile("(.*?)([a-z0-9]*) co '(.*?)'([\\s]*.*)", Pattern.CASE_INSENSITIVE);

	static final Pattern swPattern = Pattern.compile("(.*?)([a-z0-9]*) sw '(.*?)'([\\s]*.*)", Pattern.CASE_INSENSITIVE);

	static final Pattern eqPattern = Pattern.compile("(.*?)([a-z0-9]*) eq '(.*?)'([\\s]*.*)", Pattern.CASE_INSENSITIVE);

	static final Pattern prPattern = Pattern.compile(" pr([\\s]*)", Pattern.CASE_INSENSITIVE);

	static final Pattern gtPattern = Pattern.compile(" gt ", Pattern.CASE_INSENSITIVE);

	static final Pattern gePattern = Pattern.compile(" ge ", Pattern.CASE_INSENSITIVE);

	static final Pattern ltPattern = Pattern.compile(" lt ", Pattern.CASE_INSENSITIVE);

	static final Pattern lePattern = Pattern.compile(" le ", Pattern.CASE_INSENSITIVE);

	protected final JdbcTemplate jdbcTemplate;

	private NamedParameterJdbcTemplate parameterJdbcTemplate;

	private PasswordValidator passwordValidator = new DefaultPasswordValidator();

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	private final RowMapper<ScimUser> mapper = new ScimUserRowMapper();

	public JdbcScimUserProvisioning(JdbcTemplate jdbcTemplate) {
		Assert.notNull(jdbcTemplate);
		this.jdbcTemplate = jdbcTemplate;
		this.parameterJdbcTemplate = new NamedParameterJdbcTemplate(jdbcTemplate);
	}

	@Override
	public ScimUser retrieveUser(String id) {
		try {
			ScimUser u = jdbcTemplate.queryForObject(USER_BY_ID_QUERY, mapper, id);
			return u;
		}
		catch (EmptyResultDataAccessException e) {
			throw new UserNotFoundException("User " + id + " does not exist");
		}
	}

	@Override
	public Collection<ScimUser> retrieveUsers() {
		// TODO: Need to be able to build a cursor into the result
		List<ScimUser> input = jdbcTemplate.query(ALL_USERS, mapper);
		return input;
	}

	@Override
	public Collection<ScimUser> retrieveUsers(String filter) {

		String where = filter;

		// There is only one email address for now...
		where = StringUtils.arrayToDelimitedString(emailsValuePattern.split(where), "email");

		Map<String, String> values = new HashMap<String, String>();

		where = makeCaseInsensitive(where, coPattern, "%slower(%s) like :?%s", "%%%s%%", values);
		where = makeCaseInsensitive(where, swPattern, "%slower(%s) like :?%s", "%s%%", values);
		where = makeCaseInsensitive(where, eqPattern, "%slower(%s) = :?%s", "%s", values);
		where = prPattern.matcher(where).replaceAll(" is not null$1");
		where = gtPattern.matcher(where).replaceAll(" > ");
		where = gePattern.matcher(where).replaceAll(" >= ");
		where = ltPattern.matcher(where).replaceAll(" < ");
		where = lePattern.matcher(where).replaceAll(" <= ");

		logger.debug("Filtering users with SQL: '" + where + "', with parameters: " + values);

		if (where.contains("emails.")) {
			throw new UnsupportedOperationException("Filters on email address fields other than 'value' not supported");
		}

		try {
			return parameterJdbcTemplate.query(ALL_USERS + " WHERE " + where, values, mapper);
		}
		catch (DataAccessException e) {
			logger.debug("Query failed. ", e);
			throw new IllegalArgumentException("Bad filter");
		}

	}

	private String makeCaseInsensitive(String where, Pattern pattern, String template, String valueTemplate,
			Map<String, String> values) {
		String output = where;
		Matcher matcher = pattern.matcher(output);
		int count = values.size();
		while (matcher.matches()) {
			values.put("value" + count, String.format(valueTemplate, matcher.group(3).toLowerCase()));
			String query = template.replace("?", "value" + count);
			output = matcher.replaceFirst(String.format(query, matcher.group(1), matcher.group(2), matcher.group(4)));
			matcher = pattern.matcher(output);
			count++;
		}
		return output;
	}

	@Override
	public ScimUser createUser(final ScimUser user, final String password) throws InvalidPasswordException,
			InvalidUserException {

		passwordValidator.validate(password, user);
		validateUsername(user);

		logger.info("Creating new user: " + user.getUserName());

		final String id = UUID.randomUUID().toString();
		try {
			jdbcTemplate.update(CREATE_USER_SQL, new PreparedStatementSetter() {
				public void setValues(PreparedStatement ps) throws SQLException {
					ps.setString(1, id);
					ps.setInt(2, user.getVersion());
					ps.setTimestamp(3, new Timestamp(new Date().getTime()));
					ps.setTimestamp(4, new Timestamp(new Date().getTime()));
					ps.setString(5, user.getUserName());
					ps.setString(6, user.getPrimaryEmail());
					ps.setString(7, user.getName().getGivenName());
					ps.setString(8, user.getName().getFamilyName());
					ps.setBoolean(9, user.isActive());
					ps.setString(10, passwordEncoder.encode(password));
				}
			});
		}
		catch (DuplicateKeyException e) {
			throw new UserAlreadyExistsException("Username already in use (could be inactive account): "
					+ user.getUserName());
		}
		return retrieveUser(id);

	}

	private void validateUsername(final ScimUser user) throws InvalidUserException {
		if (!user.getUserName().matches("[a-z0-9_.@]+")) {
			throw new InvalidUserException("Username must be lower case alphanumeric with optional characters '._@'.");
		}
	}

	@Override
	public ScimUser updateUser(final String id, final ScimUser user) throws InvalidUserException {
		validateUsername(user);
		logger.info("Updating user " + user.getUserName());

		int updated = jdbcTemplate.update(UPDATE_USER_SQL, new PreparedStatementSetter() {
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setInt(1, user.getVersion() + 1);
				ps.setTimestamp(2, new Timestamp(new Date().getTime()));
				ps.setString(3, user.getPrimaryEmail());
				ps.setString(4, user.getName().getGivenName());
				ps.setString(5, user.getName().getFamilyName());
				ps.setBoolean(6, user.isActive());
				ps.setString(7, id);
				ps.setInt(8, user.getVersion());
			}
		});
		ScimUser result = retrieveUser(id);
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
	public boolean changePassword(final String id, String oldPassword, final String newPassword)
			throws UserNotFoundException {
		if (oldPassword != null) {
			checkPasswordMatches(id, oldPassword);
		}

		int updated = jdbcTemplate.update(CHANGE_PASSWORD_SQL, new PreparedStatementSetter() {
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setTimestamp(1, new Timestamp(new Date().getTime()));
				ps.setString(2, passwordEncoder.encode(newPassword));
				ps.setString(3, id);
			}
		});
		if (updated == 0) {
			throw new UserNotFoundException("User " + id + " does not exist");
		}
		if (updated != 1) {
			throw new IncorrectResultSizeDataAccessException(1);
		}
		return true;
	}

	// Checks the existing password for a user
	private void checkPasswordMatches(String id, String oldPassword) {
		String currentPassword;
		try {
			currentPassword = jdbcTemplate.queryForObject(READ_PASSWORD_SQL, new Object[] { id },
					new int[] { Types.VARCHAR }, String.class);
		}
		catch (IncorrectResultSizeDataAccessException e) {
			throw new UserNotFoundException("User " + id + " does not exist");
		}

		if (!passwordEncoder.matches(oldPassword, currentPassword)) {
			throw new BadCredentialsException("Old password is incorrect");
		}
	}

	@Override
	public ScimUser removeUser(String id, int version) {
		logger.info("Removing user: " + id);

		ScimUser user = retrieveUser(id);
		int updated = jdbcTemplate.update(DELETE_USER_SQL, id, version);
		if (updated == 0) {
			throw new OptimisticLockingFailureException(String.format(
					"Attempt to update a user (%s) with wrong version: expected=%d but found=%d", id,
					user.getVersion(), version));
		}
		if (updated > 1) {
			throw new IncorrectResultSizeDataAccessException(1);
		}
		user.setActive(false);
		return user;
	}

	public void setPasswordValidator(PasswordValidator passwordValidator) {
		Assert.notNull(passwordValidator, "passwordValidator cannot be null");
		this.passwordValidator = passwordValidator;
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
			ScimUser user = new ScimUser();
			user.setId(id);
			Meta meta = new Meta();
			meta.setVersion(version);
			meta.setCreated(created);
			meta.setLastModified(lastModified);
			user.setMeta(meta);
			user.setUserName(userName);
			user.addEmail(email);
			Name name = new Name();
			name.setGivenName(givenName);
			name.setFamilyName(familyName);
			user.setName(name);
			user.setActive(active);
			return user;
		}
	}
}
