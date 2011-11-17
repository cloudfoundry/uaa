package org.cloudfoundry.identity.uaa.user;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.UUID;

/**
 * @author Luke Taylor
 */
public class JdbcUaaUserDatabase implements UaaUserService, ScimUserProvisioning {
	private final Log logger = LogFactory.getLog(getClass());

	public static final String USER_FIELDS = "id,username,password,email,givenName,familyName,created,lastModified ";

	public static final String CREATE_USER_SQL =
			"insert into users (id, username, password, email, givenName, familyName) values (?,?,?,?,?,?)";
	public static final String UPDATE_USER_SQL =
            "update users set email=?, givenName=?, familyName=? where id = ?";
	// TODO: We should probably look into flagging the account rather than removing the user
	public static final String DELETE_USER_SQL = "delete from users where id = ?";
	public static final String USER_BY_ID_QUERY =
			"select " + USER_FIELDS +
			"from users " +
			"where id = ?";
	public static final String USER_BY_USERNAME_QUERY =
			"select " + USER_FIELDS +
			"from users " +
			"where username = ?";


	private JdbcTemplate jdbcTemplate;

	private final RowMapper<UaaUser> mapper = new UaaUserRowMapper();

	public JdbcUaaUserDatabase(JdbcTemplate jdbcTemplate) {
		Assert.notNull(jdbcTemplate);
		this.jdbcTemplate = jdbcTemplate;
	}

	@Override
	public ScimUser retrieveUser(String id) {
		UaaUser u = jdbcTemplate.queryForObject(USER_BY_ID_QUERY, mapper, id);
		return u.scimUser();
	}

	@Override
	public Collection<ScimUser> retrieveUsers() {
		// TODO: Need to be able to build a filter in this method
		throw new UnsupportedOperationException();
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

	@Override
	public UaaUser retrieveUserByName(String username) throws UsernameNotFoundException {
		try {
			return jdbcTemplate.queryForObject(USER_BY_USERNAME_QUERY, mapper, username);
		}
		catch (EmptyResultDataAccessException e) {
			throw new UsernameNotFoundException(username);
		}
	}

	private static final class UaaUserRowMapper implements RowMapper<UaaUser> {
		@Override
		public UaaUser mapRow(ResultSet rs, int rowNum) throws SQLException {
			return new UaaUser(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5),
					rs.getString(6), rs.getTimestamp(7), rs.getTimestamp(8));
		}
	}
}
