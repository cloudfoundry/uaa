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
package org.cloudfoundry.identity.uaa.scim;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.activation.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;
import org.springframework.util.FileCopyUtils;

/**
 * In-memory user account information storage.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
public class InMemoryScimUserProvisioning extends JdbcScimUserProvisioning implements DisposableBean {

	public InMemoryScimUserProvisioning(Map<String, UaaUser> users) {
		super(new JdbcTemplate((new DriverManagerDataSource("org.hsqldb.jdbcDriver", "jdbc:hsqldb:mem:scimusers", "sa", ""))));

		try {
			Resource sqlFile = new ClassPathResource("org/cloudfoundry/identity/uaa/schema-hsqldb.sql");
			String sql = new String(FileCopyUtils.copyToByteArray(sqlFile.getInputStream()));
			jdbcTemplate.execute(sql);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}

		setPasswordValidator(new PasswordValidator() {
			@Override
			public void validate(String password, ScimUser user) throws InvalidPasswordException {
				// accept anything
			}
		});

		for (UaaUser u: users.values()) {
			createUser(getScimUser(u), u.getPassword());
		}
	}

	@Override
	public void destroy() {
		jdbcTemplate.execute("SHUTDOWN");
	}

	/**
	 * Convert UaaUser to SCIM data.
	 */
	private ScimUser getScimUser(UaaUser user) {
		ScimUser scim = new ScimUser(user.getId(), user.getUsername(), user.getGivenName(), user.getFamilyName());
		scim.addEmail(user.getEmail());
		return scim;
	}
}
