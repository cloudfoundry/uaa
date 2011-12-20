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

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.scim.DefaultPasswordValidator;
import org.cloudfoundry.identity.uaa.scim.PasswordValidator;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.util.Assert;

/**
 *
 * @author Luke Taylor
 */
public class JdbcAuditService implements UaaAuditService {
	private final JdbcTemplate template;
	private PasswordValidator passwordValidator = new DefaultPasswordValidator();

	public JdbcAuditService(DataSource dataSource) {
		this.template = new JdbcTemplate(dataSource);
	}

	@Override
	public void userAuthenticationSuccess(UaaUser user, UaaAuthenticationDetails details) {
		Assert.notNull(user, "UaaUSer cannot be null");
		createAuditRecord(user.getId(), AuditEventType.UserAuthenticationSuccess, getOrigin(details), user.getUsername());
	}

	// Ideally we want to get to the point where details is never null, but this isn't currently possible
	// due to some OAuth authentication scenarios which don't set it.
	private String getOrigin(UaaAuthenticationDetails details) {
		return details == null ? "unknown" : details.getOrigin();
	}

	@Override
	public void userAuthenticationFailure(UaaUser user, UaaAuthenticationDetails details) {
		createAuditRecord(user.getId(), AuditEventType.UserAuthenticationFailure, details.getOrigin(), user.getUsername());
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
		createAuditRecord(name, AuditEventType.UserNotFound, details.getOrigin(), "");
	}

	private void createAuditRecord(String principal_id, AuditEventType type, String origin, String data) {
		template.update("insert into sec_audit (principal_id, event_type, origin, event_data) values (?,?,?,?)",
						principal_id, type.ordinal(), origin, data);
	}
}
