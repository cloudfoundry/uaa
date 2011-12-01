package org.cloudfoundry.identity.uaa.scim;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Meta;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Name;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class JdbcScimUserProvisioning implements ScimUserProvisioning {

	private final Log logger = LogFactory.getLog(getClass());

	static final Pattern emailsValuePattern = Pattern.compile("emails\\.value", Pattern.CASE_INSENSITIVE);
	
	static final Pattern coPattern = Pattern.compile("(.*?)([a-z0-9]*) co '(.*?)'(.*?)", Pattern.CASE_INSENSITIVE);

	static final Pattern swPattern = Pattern.compile("(.*?)([a-z0-9]*) sw '(.*?)'(.*?)", Pattern.CASE_INSENSITIVE);

	static final Pattern eqPattern = Pattern.compile("(.*?)([a-z0-9]*) eq '(.*?)'(.*?)", Pattern.CASE_INSENSITIVE);

	static final Pattern prPattern = Pattern.compile(" pr([\\s]*)", Pattern.CASE_INSENSITIVE);

	static final Pattern gtPattern = Pattern.compile(" gt ", Pattern.CASE_INSENSITIVE);

	static final Pattern gePattern = Pattern.compile(" ge ", Pattern.CASE_INSENSITIVE);

	static final Pattern ltPattern = Pattern.compile(" lt ", Pattern.CASE_INSENSITIVE);

	static final Pattern lePattern = Pattern.compile(" le ", Pattern.CASE_INSENSITIVE);

	public static final String USER_FIELDS = "id,version,created,lastModified,username,email,givenName,familyName";

	public static final String CREATE_USER_SQL =
			"insert into users ("+USER_FIELDS+",password) values (?,?,?,?,?,?,?,?,?)";
	public static final String UPDATE_USER_SQL =
            "update users set version=?, lastModified=?, email=?, givenName=?, familyName=? where id = ? and version = ?";
	// TODO: We should probably look into flagging the account rather than removing the user
	public static final String DELETE_USER_SQL = "delete from users where id = ? and version = ?";
	public static final String USER_BY_ID_QUERY =
			"select " + USER_FIELDS +
			" from users " +
			"where id = ?";
	public static final String ALL_USERS =
			"select " + USER_FIELDS +
			" from users";

	private JdbcTemplate jdbcTemplate;

	private PasswordValidator passwordValidator = new DefaultPasswordValidator();

	private final RowMapper<ScimUser> mapper = new ScimUserRowMapper();

	public JdbcScimUserProvisioning(JdbcTemplate jdbcTemplate) {
		Assert.notNull(jdbcTemplate);
		this.jdbcTemplate = jdbcTemplate;
	}

	@Override
	public ScimUser retrieveUser(String id) {
		ScimUser u = jdbcTemplate.queryForObject(USER_BY_ID_QUERY, mapper, id);
		return u;
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
		
		where = makeCaseInsensitive(where, coPattern, "%slower(%s) like '%%%s%%'%s");
		where = makeCaseInsensitive(where, swPattern, "%slower(%s) like '%s%%'%s");
		where = makeCaseInsensitive(where, eqPattern, "%slower(%s) = '%s'%s");
		where = prPattern.matcher(where).replaceAll(" is not null$1");
		where = gtPattern.matcher(where).replaceAll(" > ");
		where = gePattern.matcher(where).replaceAll(" >= ");
		where = ltPattern.matcher(where).replaceAll(" < ");
		where = lePattern.matcher(where).replaceAll(" <= ");

		logger.debug("Filtering users with SQL: " + where);

		if (where.contains("emails.")) {
			throw new UnsupportedOperationException("Filters on email address fields other than 'value' not supported");
		}

		List<ScimUser> input = jdbcTemplate.query(ALL_USERS + " WHERE " + where, mapper);
		return input;

	}

	private String makeCaseInsensitive(String where, Pattern pattern, String template) {
		Matcher matcher = pattern.matcher(where);
		if (!matcher.matches()) {
			return where;
		}
		return matcher.replaceAll(String.format(template, matcher.group(1), matcher.group(2), matcher.group(3).toLowerCase(), matcher.group(4)));
	}

	@Override
	public ScimUser createUser(final ScimUser user, final String password) {

		passwordValidator.validate(password, user);
		if (!user.getUserName().matches("[a-z0-9]+")) {
			throw new ScimException("Username must be lower case alphanumeric.", HttpStatus.BAD_REQUEST);
		}

		final String id = UUID.randomUUID().toString();
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
				ps.setString(9, password);
			}
		});
		return retrieveUser(id);

	}

	@Override
	public ScimUser updateUser(final String id, final ScimUser user) {
		int updated = jdbcTemplate.update(UPDATE_USER_SQL, new PreparedStatementSetter() {
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setInt(1, user.getVersion()+1);
				ps.setTimestamp(2, new Timestamp(new Date().getTime()));
				ps.setString(3, user.getPrimaryEmail());
				ps.setString(4, user.getName().getGivenName());
				ps.setString(5, user.getName().getFamilyName());
				ps.setString(6, id);
				ps.setInt(7, user.getVersion());
			}
		});
		ScimUser result = retrieveUser(id);
		if (updated==0) {
			throw new OptimisticLockingFailureException(String.format("Attempt to update a user (%s) with wrong version: expected=%d but found=%d", id, result.getVersion(), user.getVersion()));
		}
		if (updated>1) {
			throw new IncorrectResultSizeDataAccessException(1);
		}
		return result;
	}

	@Override
	public ScimUser removeUser(String id, int version) {
		ScimUser user = retrieveUser(id);
		int updated = jdbcTemplate.update(DELETE_USER_SQL, id, version);
		if (updated==0) {
			throw new OptimisticLockingFailureException(String.format("Attempt to update a user (%s) with wrong version: expected=%d but found=%d", id, user.getVersion(), version));
		}
		if (updated>1) {
			throw new IncorrectResultSizeDataAccessException(1);
		}
		return user;
	}

	public void setPasswordValidator(PasswordValidator passwordValidator) {
		Assert.notNull(passwordValidator, "passwordValidator cannot be null");
		this.passwordValidator = passwordValidator;
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
			return user;
		}
	}
}
