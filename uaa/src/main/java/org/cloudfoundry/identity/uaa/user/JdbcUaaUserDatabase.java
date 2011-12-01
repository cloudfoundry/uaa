/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.user;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class JdbcUaaUserDatabase implements UaaUserDatabase {

	public static final String USER_FIELDS = "id,username,password,email,givenName,familyName,created,lastModified ";

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
