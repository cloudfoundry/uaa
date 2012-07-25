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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.util.Assert;

/**
 * An audit service that subscribes to audit events but only saves enough data to answer queries about consecutive
 * failed logins.
 * 
 * @author Dave Syer
 */
public class JdbcFailedLoginCountingAuditService implements UaaAuditService {

	private final JdbcTemplate template;

	private int saveDataPeriodMillis = 2 * 3600 * 1000; // 2hr

	public JdbcFailedLoginCountingAuditService(DataSource dataSource) {
		this.template = new JdbcTemplate(dataSource);
	}

	/**
	 * @param saveDataPeriodMillis the period in milliseconds to set
	 */
	public void setSaveDataPeriodMillis(int saveDataPeriodMillis) {
		this.saveDataPeriodMillis = saveDataPeriodMillis;
	}

	@Override
	public void userAuthenticationSuccess(UaaUser user, UaaAuthenticationDetails details) {
		Assert.notNull(user, "UaaUser cannot be null");
		// Reset the data for this user
		template.update("delete from sec_audit where principal_id=?", user.getId());
	}

	// Ideally we want to get to the point where details is never null, but this isn't currently possible
	// due to some OAuth authentication scenarios which don't set it.
	private String getOrigin(UaaAuthenticationDetails details) {
		return details == null ? "unknown" : details.getOrigin();
	}

	@Override
	public void userAuthenticationFailure(UaaUser user, UaaAuthenticationDetails details) {
		if (user == null) {
			return;
		}
		template.update("delete from sec_audit where created < ?", new Timestamp(System.currentTimeMillis()
				- saveDataPeriodMillis));
		template.update("insert into sec_audit (principal_id, event_type, origin, event_data) values (?,?,?,?)",
				user.getId(), AuditEventType.UserAuthenticationFailure.getCode(), getOrigin(details), user.getUsername());
	}

	@Override
	public void userNotFound(String name, UaaAuthenticationDetails details) {
	}

	@Override
	public void principalAuthenticationFailure(String name, UaaAuthenticationDetails details) {
	}

	@Override
	public void principalNotFound(String name, UaaAuthenticationDetails details) {
	}

	@Override
	public List<AuditEvent> find(String principal, long after) {
		return template.query("select event_type, principal_id, origin, event_data, created from sec_audit where "
				+ "principal_id=? and created > ? order by created desc", new AuditEventRowMapper(), principal,
				new Timestamp(after));
	}

	private class AuditEventRowMapper implements RowMapper<AuditEvent> {
		@Override
		public AuditEvent mapRow(ResultSet rs, int rowNum) throws SQLException {
			String principalId = rs.getString(2);
			principalId = principalId == null ? null : principalId.trim();
			String origin = rs.getString(3);
			origin = origin == null ? null : origin.trim();
			String data = rs.getString(4);
			data = data == null ? null : data.trim();
			return new AuditEvent(AuditEventType.fromCode(rs.getInt(1)), principalId, origin, data, rs.getTimestamp(5)
					.getTime());
		}
	}
}
