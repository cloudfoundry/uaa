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
package org.cloudfoundry.identity.uaa.user;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author Luke Taylor
 * @author Dave Syer
 * @author Vidya Valmikinathan
 */
public class JdbcUaaUserDatabase implements UaaUserDatabase {

	public static final String USER_FIELDS = "id,username,password,email,givenName,familyName,created,lastModified ";

	public static final String DEFAULT_USER_BY_USERNAME_QUERY = "select " + USER_FIELDS + "from users "
			+ "where lower(username) = ? and active=true";

	public static final String DEFAULT_USER_AUTHORITIES_QUERY = "select authorities from users where id = ?";
	
	private String userAuthoritiesQuery = DEFAULT_USER_AUTHORITIES_QUERY;

	private String userByUserNameQuery = DEFAULT_USER_BY_USERNAME_QUERY;

	private JdbcTemplate jdbcTemplate;

	private final RowMapper<UaaUser> mapper = new UaaUserRowMapper();

	private Set<String> defaultAuthorities = new HashSet<String>();
	
	public void setUserByUserNameQuery(String userByUserNameQuery) {
		this.userByUserNameQuery = userByUserNameQuery;
	}
	
	public void setUserAuthoritiesQuery(String userAuthoritiesQuery) {
		this.userAuthoritiesQuery = userAuthoritiesQuery;
	}

	public void setDefaultAuthorities(Set<String> defaultAuthorities) {
		this.defaultAuthorities = defaultAuthorities;
	}

	public JdbcUaaUserDatabase(JdbcTemplate jdbcTemplate) {
		Assert.notNull(jdbcTemplate);
		this.jdbcTemplate = jdbcTemplate;
	}

	@Override
	public UaaUser retrieveUserByName(String username) throws UsernameNotFoundException {
		try {
			return jdbcTemplate.queryForObject(userByUserNameQuery, mapper, username.toLowerCase(Locale.US));
		}
		catch (EmptyResultDataAccessException e) {
			throw new UsernameNotFoundException(username);
		}
	}

	private final class UaaUserRowMapper implements RowMapper<UaaUser> {
		@Override
		public UaaUser mapRow(ResultSet rs, int rowNum) throws SQLException {
			String id = rs.getString(1);
			List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(getAuthorities(id));
			return new UaaUser(id, rs.getString(2), rs.getString(3), rs.getString(4),
					authorities, rs.getString(5), rs.getString(6),
					rs.getTimestamp(7), rs.getTimestamp(8));
		}

		private String getAuthorities(final String userId) {
			List<String> authorities;
			try {
				authorities = jdbcTemplate.queryForList(userAuthoritiesQuery, String.class, userId);
			} catch (EmptyResultDataAccessException ex) {
				authorities = Collections.<String>emptyList();
			}
			authorities.addAll(defaultAuthorities);
			return StringUtils.collectionToCommaDelimitedString(new HashSet<String>(authorities));
		}
	}
}
