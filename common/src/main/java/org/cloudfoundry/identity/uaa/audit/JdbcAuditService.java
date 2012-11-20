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
package org.cloudfoundry.identity.uaa.audit;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.Authentication;
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

	private String getOrigin(Principal principal) {
		if (principal instanceof Authentication) {
			Authentication caller = (Authentication) principal;
			if (caller!=null && caller.getDetails() instanceof UaaAuthenticationDetails) {
				return getOrigin((UaaAuthenticationDetails) caller.getDetails());
			}
		} 
		return principal==null ? null : principal.getName();
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
	public void passwordChangeSuccess(String message, UaaUser user, Principal caller) {
		createAuditRecord(user.getUsername(), AuditEventType.PasswordChangeSuccess, getOrigin(caller), message);
	}
	
	@Override
	public void passwordChangeFailure(String message, Principal caller) {		
		createAuditRecord(caller.getName(), AuditEventType.PasswordChangeFailure, getOrigin(caller), message);
	}
	
	@Override
	public void passwordChangeFailure(String message, UaaUser user, Principal caller) {
		createAuditRecord(user.getUsername(), AuditEventType.PasswordChangeFailure, getOrigin(caller), message);
	}

	@Override
	public List<AuditEvent> find(String principal, long after) {
		return template.query("select event_type, principal_id, origin, event_data, created from sec_audit where " +
								"principal_id=? and created > ? order by created desc", new AuditEventRowMapper(), principal, new Timestamp(after));
	}

	private void createAuditRecord(String principal_id, AuditEventType type, String origin) {
		origin = origin==null ? "" : origin;
		origin = origin.length()>255 ? origin.substring(0, 255) : origin;
		template.update("insert into sec_audit (principal_id, event_type, origin) values (?,?,?)",
						principal_id, type.getCode(), origin);
	}

	private void createAuditRecord(String principal_id, AuditEventType type, String origin, String data) {
		origin = origin==null ? "" : origin;
		origin = origin.length()>255 ? origin.substring(0, 255) : origin;
		data = data==null ? "" : data;
		data = data.length()>255 ? data.substring(0, 255) : data;
		template.update("insert into sec_audit (principal_id, event_type, origin, event_data) values (?,?,?,?)",
						principal_id, type.getCode(), origin, data);
	}

	private class AuditEventRowMapper implements RowMapper<AuditEvent> {
		@Override
		public AuditEvent mapRow(ResultSet rs, int rowNum) throws SQLException {
			String principalId = rs.getString(2);
			principalId = principalId==null ? null : principalId.trim();
			String origin = rs.getString(3);
			origin = origin==null ? null : origin.trim();
			String data = rs.getString(4);
			data = data==null ? null : data.trim();
			return new AuditEvent(AuditEventType.fromCode(rs.getInt(1)), principalId, origin,
					data, rs.getTimestamp(5).getTime());
		}
	}
}
