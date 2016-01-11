/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * @author Luke Taylor
 * @author Dave Syer
 * @author Vidya Valmikinathan
 */
public class JdbcUaaUserDatabase implements UaaUserDatabase {

    public static final String USER_FIELDS = "id,username,password,email,givenName,familyName,created,lastModified,authorities,origin,external_id,verified,identity_zone_id,salt,passwd_lastmodified,phoneNumber,legacy_verification_behavior ";

    public static final String DEFAULT_USER_BY_USERNAME_QUERY = "select " + USER_FIELDS + "from users "
                    + "where lower(username) = ? and active=? and origin=? and identity_zone_id=?";

    public static final String DEFAULT_USER_BY_ID_QUERY = "select " + USER_FIELDS + "from users "
        + "where id = ? and active=?";

    public static final String DEFAULT_USER_BY_EMAIL_AND_ORIGIN_QUERY = "select " + USER_FIELDS + "from users "
            + "where lower(email)=? and active=? and origin=? and identity_zone_id=?";

    private String userAuthoritiesQuery = null;

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
    public UaaUser retrieveUserByName(String username, String origin) throws UsernameNotFoundException {
        try {
            return jdbcTemplate.queryForObject(userByUserNameQuery, mapper, username.toLowerCase(Locale.US), true, origin, IdentityZoneHolder.get().getId());
        } catch (EmptyResultDataAccessException e) {
            throw new UsernameNotFoundException(username);
        }
    }

    @Override
    public UaaUser retrieveUserById(String id) throws UsernameNotFoundException {
        try {
            return jdbcTemplate.queryForObject(DEFAULT_USER_BY_ID_QUERY, mapper, id, true);
        } catch (EmptyResultDataAccessException e) {
            throw new UsernameNotFoundException(id);
        }
    }

    @Override
    public UaaUser retrieveUserByEmail(String email, String origin) throws UsernameNotFoundException {
        List<UaaUser> results = jdbcTemplate.query(DEFAULT_USER_BY_EMAIL_AND_ORIGIN_QUERY, mapper, email.toLowerCase(Locale.US), true, origin, IdentityZoneHolder.get().getId());
        if(results.size() == 0) {
            return null;
        }
        else if(results.size() == 1) {
            return results.get(0);
        }
        else {
            throw new IncorrectResultSizeDataAccessException(String.format("Multiple users match email=%s origin=%s", email, origin), 1, results.size());
        }
    }

    private final class UaaUserRowMapper implements RowMapper<UaaUser> {
        @Override
        public UaaUser mapRow(ResultSet rs, int rowNum) throws SQLException {
            String id = rs.getString(1);
            UaaUserPrototype prototype = new UaaUserPrototype().withId(id)
                    .withUsername(rs.getString(2))
                    .withPassword(rs.getString(3))
                    .withEmail(rs.getString(4))
                    .withGivenName(rs.getString(5))
                    .withFamilyName(rs.getString(6))
                    .withCreated(rs.getTimestamp(7))
                    .withModified(rs.getTimestamp(8))
                    .withAuthorities(getDefaultAuthorities(rs.getString(9)))
                    .withOrigin(rs.getString(10))
                    .withExternalId(rs.getString(11))
                    .withVerified(rs.getBoolean(12))
                    .withZoneId(rs.getString(13))
                    .withSalt(rs.getString(14))
                    .withPasswordLastModified(rs.getTimestamp(15))
                    .withPhoneNumber(rs.getString(16))
                    .withLegacyVerificationBehavior(rs.getBoolean(17))
                    ;

            if (userAuthoritiesQuery == null) {
                return new UaaUser(prototype);
            } else {
                List<GrantedAuthority> authorities = AuthorityUtils
                                .commaSeparatedStringToAuthorityList(getAuthorities(id));
                return new UaaUser(prototype.withAuthorities(authorities));
            }
        }

        private List<GrantedAuthority> getDefaultAuthorities(String defaultAuth) {
            List<String> authorities = new ArrayList<String>();
            authorities.addAll(StringUtils.commaDelimitedListToSet(defaultAuth));
            authorities.addAll(defaultAuthorities);
            String authsString = StringUtils.collectionToCommaDelimitedString(new HashSet<String>(authorities));
            return AuthorityUtils.commaSeparatedStringToAuthorityList(authsString);
        }

        private String getAuthorities(final String userId) {
            List<String> authorities;
            try {
                authorities = jdbcTemplate.queryForList(userAuthoritiesQuery, String.class, userId);
            } catch (EmptyResultDataAccessException ex) {
                authorities = Collections.<String> emptyList();
            }
            authorities.addAll(defaultAuthorities);
            return StringUtils.collectionToCommaDelimitedString(new HashSet<String>(authorities));
        }
    }
}
