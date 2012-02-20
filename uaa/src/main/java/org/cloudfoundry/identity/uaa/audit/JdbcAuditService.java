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
package org.cloudfoundry.identity.uaa.audit;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.util.Assert;

/**
 *
 * @author Luke Taylor
 */
public class JdbcAuditService implements UaaAuditService {

	private final JdbcTemplate template;

	public JdbcAuditService(DataSource dataSource) {
		this.template = new JdbcTemplate(dataSource);
	}

	@Override
	public void userAuthenticationSuccess(UaaUser user, UaaAuthenticationDetails details) {
		Assert.notNull(user, "UaaUser cannot be null");
		createAuditRecord(user.getId(), AuditEventType.UserAuthenticationSuccess, getOrigin(details), user.getUsername());
	}

	// Ideally we want to get to the point where details is never null, but this isn't currently possible
	// due to some OAuth authentication scenarios which don't set it.
	private String getOrigin(UaaAuthenticationDetails details) {
		return details == null ? "unknown" : details.getOrigin();
	}

	@Override
	public void userAuthenticationFailure(UaaUser user, UaaAuthenticationDetails details) {
		if (user==null) {
			userNotFound("<UNKNOWN>", details);
			return;
		}
		createAuditRecord(user.getId(), AuditEventType.UserAuthenticationFailure, getOrigin(details), user.getUsername());
	}

	@Override
	public void userNotFound(String name, UaaAuthenticationDetails details) {
		try {
			// Store hash of name, to conceal accidental entry of sensitive info (e.g. password)
			name = Utf8.decode(Base64.encode(MessageDigest.getInstance("SHA-1").digest(Utf8.encode(name))));
		}
		catch (NoSuchAlgorithmException shouldNeverHappen) {
			name = "NOSHA";
		}
		createAuditRecord(name, AuditEventType.UserNotFound, getOrigin(details), "");
	}

	@Override
	public void principalAuthenticationFailure(String name, UaaAuthenticationDetails details) {
		createAuditRecord(name, AuditEventType.PrincipalAuthenticationFailure, getOrigin(details));
	}

	@Override
	public void principalNotFound(String name, UaaAuthenticationDetails details) {
		createAuditRecord(name, AuditEventType.PrincipalNotFound, getOrigin(details));
	}

	@Override
	public List<AuditEvent> find(String principal, long after) {
		return template.query("select event_type, principal_id, origin, event_data, created from sec_audit where " +
								"principal_id=? and created > ? order by created desc", new AuditEventRowMapper(), principal, new Timestamp(after));
	}

	private void createAuditRecord(String principal_id, AuditEventType type, String origin) {
		template.update("insert into sec_audit (principal_id, event_type, origin) values (?,?,?)",
						principal_id, type.getCode(), origin);
	}

	private void createAuditRecord(String principal_id, AuditEventType type, String origin, String data) {
		template.update("insert into sec_audit (principal_id, event_type, origin, event_data) values (?,?,?,?)",
						principal_id, type.getCode(), origin, data);
	}

	private class AuditEventRowMapper implements RowMapper<AuditEvent> {
		@Override
		public AuditEvent mapRow(ResultSet rs, int rowNum) throws SQLException {
			return new AuditEvent(AuditEventType.fromCode(rs.getInt(1)), rs.getString(2), rs.getString(3),
					rs.getString(4), rs.getTimestamp(5).getTime());
		}
	}
}
