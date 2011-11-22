package org.cloudfoundry.identity.uaa.scim;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Name;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class JdbcScimUserProvisioning implements ScimUserProvisioning {
	private final Log logger = LogFactory.getLog(getClass());

	public static final String USER_FIELDS = "id,username,email,givenName,familyName";

	public static final String CREATE_USER_SQL =
			"insert into users (id, username, password, email, givenName, familyName) values (?,?,?,?,?,?)";
	public static final String UPDATE_USER_SQL =
            "update users set email=?, givenName=?, familyName=? where id = ?";
	// TODO: We should probably look into flagging the account rather than removing the user
	public static final String DELETE_USER_SQL = "delete from users where id = ?";
	public static final String USER_BY_ID_QUERY =
			"select " + USER_FIELDS +
			" from users " +
			"where id = ?";
	public static final String ALL_USERS =
			"select " + USER_FIELDS +
			" from users";

	private JdbcTemplate jdbcTemplate;

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

		String where = filter.replace(" eq ", " = ").replace(" pr", " is not null ").replace(" ge ", " >= ")
				.replace(" le ", " <= ").replace(" gt ", " > ").replace(" lt ", " < ")
				.replaceAll(" co '(.*?)'", " like '%$1%'").replaceAll(" sw '(.*?)'", " like '$1%'")
				// There is only one email address for now...
				.replace("emails.value", "email");

		logger.debug("Filtering users with SQL: " + where);
		
		if (where.contains("emails.")) {
			throw new UnsupportedOperationException("Filters on email adress fields other than 'value' not supported");
		}

		List<ScimUser> input = jdbcTemplate.query(ALL_USERS + " WHERE " + where, mapper);
		return input;

	}

	@Override
	public ScimUser createUser(final ScimUser user, final String password) {
		final String id = UUID.randomUUID().toString();
		jdbcTemplate.update(CREATE_USER_SQL, new PreparedStatementSetter() {
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setString(1, id);
				ps.setString(2, user.getUserName());
				ps.setString(3, password);
				ps.setString(4, user.getPrimaryEmail());
				ps.setString(5, user.getName().getGivenName());
				ps.setString(6, user.getName().getFamilyName());
			}
		});
		return retrieveUser(id);
	}

	@Override
	public ScimUser updateUser(final String id, final ScimUser user) {
		jdbcTemplate.update(UPDATE_USER_SQL, new PreparedStatementSetter() {
			public void setValues(PreparedStatement ps) throws SQLException {
				ps.setString(1, user.getPrimaryEmail());
				ps.setString(2, user.getName().getGivenName());
				ps.setString(3, user.getName().getFamilyName());
				ps.setString(4, id);
			}
		});
		return retrieveUser(id);
	}

	@Override
	public ScimUser removeUser(String id) {
		ScimUser user = retrieveUser(id);
		jdbcTemplate.update(DELETE_USER_SQL, id);
		return user;
	}

	private static final class ScimUserRowMapper implements RowMapper<ScimUser> {
		@Override
		public ScimUser mapRow(ResultSet rs, int rowNum) throws SQLException {
			String id = rs.getString(1);
			String userName = rs.getString(2);
			String email = rs.getString(3);
			String givenName = rs.getString(4);
			String familyName = rs.getString(5);
			ScimUser user = new ScimUser();
			user.setId(id);
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
