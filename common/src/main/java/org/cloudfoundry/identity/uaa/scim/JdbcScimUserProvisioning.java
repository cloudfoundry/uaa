/*
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
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Group;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Name;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.dao.DataAccessException;
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
import org.springframework.util.StringUtils;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class JdbcScimUserProvisioning implements ScimUserProvisioning {

	private final Log logger = LogFactory.getLog(getClass());

	public static final String USER_FIELDS = "id,version,created,lastModified,username,email,givenName,familyName,active,authorities,phoneNumber";

	public static final String CREATE_USER_SQL = "insert into users (" + USER_FIELDS
			+ ",password) values (?,?,?,?,?,?,?,?,?,?,?,?)";

	public static final String UPDATE_USER_SQL = "update users set version=?, lastModified=?, email=?, givenName=?, familyName=?, active=?, authorities=?, phoneNumber=? where id=? and version=?";

	public static final String DEACTIVATE_USER_SQL = "update users set active=false where id=?";

    public static final String DELETE_USER_SQL = "delete from users where id=?";

    public static final String ID_FOR_DELETED_USER_SQL = "select id from users where userName=? and active=false";

	public static final String CHANGE_PASSWORD_SQL = "update users set lastModified=?, password=? where id=?";

	public static final String READ_PASSWORD_SQL = "select password from users where id=?";

	public static final String USER_BY_ID_QUERY = "select " + USER_FIELDS + " from users " + "where id=?";

	public static final String ALL_USERS = "select " + USER_FIELDS + " from users";

	/*
	 * Filter regexes for turning SCIM filters into SQL:
	 */

	static final Pattern emailsValuePattern = Pattern.compile("emails\\.value", Pattern.CASE_INSENSITIVE);

	static final Pattern groupsValuePattern = Pattern.compile("groups\\.display", Pattern.CASE_INSENSITIVE);

	static final Pattern phoneNumbersValuePattern = Pattern.compile("phoneNumbers\\.value", Pattern.CASE_INSENSITIVE);

	static final Pattern coPattern = Pattern.compile("(.*?)([a-z0-9]*) co '(.*?)'([\\s]*.*)", Pattern.CASE_INSENSITIVE);

	static final Pattern swPattern = Pattern.compile("(.*?)([a-z0-9]*) sw '(.*?)'([\\s]*.*)", Pattern.CASE_INSENSITIVE);

	static final Pattern eqPattern = Pattern.compile("(.*?)([a-z0-9]*) eq '(.*?)'([\\s]*.*)", Pattern.CASE_INSENSITIVE);

	static final Pattern boPattern = Pattern.compile("(.*?)([a-z0-9]*) eq (true|false)([\\s]*.*)",
			Pattern.CASE_INSENSITIVE);

	static final Pattern metaPattern = Pattern.compile("(.*?)meta\\.([a-z0-9]*) (\\S) '(.*?)'([\\s]*.*)",
			Pattern.CASE_INSENSITIVE);

	static final Pattern prPattern = Pattern.compile(" pr([\\s]*)", Pattern.CASE_INSENSITIVE);

	static final Pattern gtPattern = Pattern.compile(" gt ", Pattern.CASE_INSENSITIVE);

	static final Pattern gePattern = Pattern.compile(" ge ", Pattern.CASE_INSENSITIVE);

	static final Pattern ltPattern = Pattern.compile(" lt ", Pattern.CASE_INSENSITIVE);

	static final Pattern lePattern = Pattern.compile(" le ", Pattern.CASE_INSENSITIVE);

	static final Pattern unquotedEq = Pattern.compile("(id|username|email|givenName|familyName) eq [^'].*",
			Pattern.CASE_INSENSITIVE);

	private static final DateFormat TIMESTAMP_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

	protected final JdbcTemplate jdbcTemplate;

	private PasswordValidator passwordValidator = new DefaultPasswordValidator();

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private boolean deactivateOnDelete = true;

	private final RowMapper<ScimUser> mapper = new ScimUserRowMapper();

	public JdbcScimUserProvisioning(JdbcTemplate jdbcTemplate) {
		Assert.notNull(jdbcTemplate);
		this.jdbcTemplate = jdbcTemplate;
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
	public List<ScimUser> retrieveUsers() {
		List<ScimUser> input = new JdbcPagingList<ScimUser>(jdbcTemplate, ALL_USERS + " ORDER by created ASC", mapper,
				200);
		return input;
	}

	@Override
	public List<ScimUser> retrieveUsers(String filter) {
		return retrieveUsers(filter, null, true);
	}

	@Override
	public List<ScimUser> retrieveUsers(String filter, String sortBy, boolean ascending) {
		String where = filter;

		// Single quotes for literals
		where = where.replaceAll("\"", "'");

		if (unquotedEq.matcher(where).matches()) {
			throw new IllegalArgumentException("Eq argument in filter (" + filter + ") must be quoted");
		}

		if (sortBy != null) {
			// Need to add "asc" or "desc" explicitly to ensure that the pattern splitting below works
			where = where + " order by " + sortBy + (ascending ? " asc" : " desc");
		}

		// There is only one email address for now...
		where = StringUtils.arrayToDelimitedString(emailsValuePattern.split(where), "email");
		// There is only one field in groups for now...
		where = StringUtils.arrayToDelimitedString(groupsValuePattern.split(where), "authorities");
		// There is only one phone number for now...
		where = StringUtils.arrayToDelimitedString(phoneNumbersValuePattern.split(where), "phoneNumber");

		Map<String, Object> values = new HashMap<String, Object>();

		where = makeCaseInsensitive(where, coPattern, "%slower(%s) like :?%s", "%%%s%%", values);
		where = makeCaseInsensitive(where, swPattern, "%slower(%s) like :?%s", "%s%%", values);
		where = makeCaseInsensitive(where, eqPattern, "%slower(%s) = :?%s", "%s", values);
		where = makeBooleans(where, boPattern, "%s%s = :?%s", values);
		where = prPattern.matcher(where).replaceAll(" is not null$1");
		where = gtPattern.matcher(where).replaceAll(" > ");
		where = gePattern.matcher(where).replaceAll(" >= ");
		where = ltPattern.matcher(where).replaceAll(" < ");
		where = lePattern.matcher(where).replaceAll(" <= ");
		// This will catch equality of number literals
		where = where.replaceAll(" eq ", " = ");
		where = makeTimestamps(where, metaPattern, "%s%s %s :?%s", values);
		where = where.replaceAll("meta\\.", "");

		logger.debug("Filtering users with SQL: [" + where + "], and parameters: " + values);

		if (where.contains("emails.")) {
			throw new UnsupportedOperationException("Filters on email address fields other than 'value' not supported");
		}

		if (where.contains("phoneNumbers.")) {
			throw new UnsupportedOperationException("Filters on phone number fields other than 'value' not supported");
		}

		try {
			// Default order is by created date descending
			String order = sortBy == null ? " ORDER BY created desc" : "";
			return new JdbcPagingList<ScimUser>(jdbcTemplate, ALL_USERS + " WHERE " + where + order, values, mapper,
					200);
		}
		catch (DataAccessException e) {
			logger.debug("Filter '" + filter + "' generated invalid SQL", e);
			throw new IllegalArgumentException("Invalid filter: " + filter);
		}
	}

	private String makeTimestamps(String where, Pattern pattern, String template, Map<String, Object> values) {
		String output = where;
		Matcher matcher = pattern.matcher(output);
		int count = values.size();
		while (matcher.matches()) {
			String property = matcher.group(2);
			Object value = matcher.group(4);
			if (property.equals("created") || property.equals("lastModified")) {
				try {
					value = TIMESTAMP_FORMAT.parse((String) value);
				}
				catch (ParseException e) {
					// ignore
				}
			}
			values.put("value" + count, value);
			String query = template.replace("?", "value" + count);
			output = matcher.replaceFirst(String.format(query, matcher.group(1), property, matcher.group(3),
					matcher.group(5)));
			matcher = pattern.matcher(output);
			count++;
		}
		return output;
	}

	private String makeCaseInsensitive(String where, Pattern pattern, String template, String valueTemplate,
			Map<String, Object> values) {
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

	private String makeBooleans(String where, Pattern pattern, String template, Map<String, Object> values) {
		String output = where;
		Matcher matcher = pattern.matcher(output);
		int count = values.size();
		while (matcher.matches()) {
			values.put("value" + count, Boolean.valueOf(matcher.group(3).toLowerCase()));
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
		validate(user);

		logger.info("Creating new user: " + user.getUserName());
		final String authorities = getAuthorities(user);

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
					ps.setString(10, authorities);
					String phoneNumber = extractPhoneNumber(user);
					ps.setString(11, phoneNumber);
					ps.setString(12, passwordEncoder.encode(password));
				}

			});
		}
		catch (DuplicateKeyException e) {
			throw new UserAlreadyExistsException("Username already in use (could be inactive account): "
					+ user.getUserName());
		}
		return retrieveUser(id);

	}

	private String getAuthorities(ScimUser user) {
		// Preserve simple implementation based only on uaa user type
		normalizeGroups(user);
		Set<String> set = new LinkedHashSet<String>();
		// Augment with explicit group membership
		if (user.getGroups()!=null) {
			for (Group group : user.getGroups()) {
				set.add(group.getDisplay());
			}
		}
		return StringUtils.collectionToCommaDelimitedString(set);
	}

	private void validate(final ScimUser user) throws InvalidUserException {
		if (!user.getUserName().matches("[a-z0-9+-_.@]+")) {
			throw new InvalidUserException("Username must be lower case alphanumeric with optional characters '._@'.");
		}
		if (user.getEmails()==null || user.getEmails().isEmpty()) {
			throw new InvalidUserException("An email must be provided.");
		}
		if (user.getName()==null || user.getName().getFamilyName()==null || user.getName().getGivenName()==null) {
			throw new InvalidUserException("A given name and a family name must be provided.");
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
	public ScimUser updateUser(final String id, final ScimUser user) throws InvalidUserException {
		validate(user);
		logger.info("Updating user " + user.getUserName());
		final String authorities = getAuthorities(user);
		
		int updated = jdbcTemplate.update(UPDATE_USER_SQL, new PreparedStatementSetter() {
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setInt(1, user.getVersion() + 1);
				ps.setTimestamp(2, new Timestamp(new Date().getTime()));
				ps.setString(3, user.getPrimaryEmail());
				ps.setString(4, user.getName().getGivenName());
				ps.setString(5, user.getName().getFamilyName());
				ps.setBoolean(6, user.isActive());
				ps.setString(7, authorities);
				ps.setString(8, extractPhoneNumber(user));
				ps.setString(9, id);
				ps.setInt(10, user.getVersion());
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
		ScimUser user = retrieveUser(id);
        return deactivateOnDelete ? deactivateUser(user, version) : deleteUser(user, version);
	}

    private ScimUser deactivateUser(ScimUser user, int version) {
        logger.info("Deactivating user: " + user.getId());
        int updated;
        if (version < 0) {
            // Ignore
            updated = jdbcTemplate.update(DEACTIVATE_USER_SQL, user.getId());
        }
        else {
            updated = jdbcTemplate.update(DEACTIVATE_USER_SQL + " and version=?", user.getId(), version);
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

    private ScimUser deleteUser(ScimUser user, int version) {
        logger.info("Deleting user: " + user.getId());
        int updated;

        if (version < 0) {
            updated = jdbcTemplate.update(DELETE_USER_SQL, user.getId());
        }
        else {
            updated = jdbcTemplate.update(DELETE_USER_SQL + " and version=?", user.getId(), version);
        }
        if (updated == 0) {
            throw new OptimisticLockingFailureException(String.format(
                    "Attempt to update a user (%s) with wrong version: expected=%d but found=%d", user.getId(),
                    user.getVersion(), version));
        }
        return user;
    }

    public void setDeactivateOnDelete (boolean deactivateOnDelete) {
        this.deactivateOnDelete = deactivateOnDelete;
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

	private void normalizeGroups(ScimUser user) {
		Set<Group> groups = new LinkedHashSet<Group>();
		if (user.getGroups()!=null) {
			groups.addAll(user.getGroups());
		}
		// Everyone is a user
		groups.add(new Group(null, UaaAuthority.UAA_USER.getAuthority()));
		if (user.getUserType()!=null && user.getUserType().contains("admin")) {
			// Some people are also admins
			groups.add(new Group(null, UaaAuthority.UAA_ADMIN.getAuthority()));
		}
		user.setGroups(new ArrayList<Group>(groups));
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
			String authorities = rs.getString(10);
			String phoneNumber = rs.getString(11);
			ScimUser user = new ScimUser();
			user.setId(id);
			ScimMeta meta = new ScimMeta();
			meta.setVersion(version);
			meta.setCreated(created);
			meta.setLastModified(lastModified);
			user.setMeta(meta);
			user.setUserName(userName);
			user.addEmail(email);
			if (phoneNumber != null) {
				user.addPhoneNumber(phoneNumber);
			}
			Name name = new Name();
			name.setGivenName(givenName);
			name.setFamilyName(familyName);
			user.setName(name);
			user.setActive(active);
			setAuthorities(user, authorities);
			return user;
		}

		private void setAuthorities(ScimUser user, String authorities) {
			if (authorities==null) {
				return;
			}
			user.setUserType(UaaAuthority.fromAuthorities(authorities).getUserType());
			List<Group> groups = new ArrayList<Group>();
			for (String group : authorities.split(",")) {
				groups.add(new Group(null, group.trim()));
			}
			if (!groups.isEmpty()) {
				user.setGroups(groups);
			}
		}

	}

}
