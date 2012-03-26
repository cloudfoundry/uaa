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

import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.jdbc.core.JdbcOperations;

/**
 * Utility to insert an admin user in the database if it is empty. The {@link #start()} method executes on the
 * {@link SmartLifecycle} callback from Spring if included as a bean definition in an application context. Any other
 * components that rely on an admin user being present should wait until after this component has started (e.g. by
 * specifying a later startup phase),
 * 
 * @author Dave Syer
 * 
 */
public class JdbcUaaAdminUserBootstrap implements SmartLifecycle {

	private static final Log logger = LogFactory.getLog(JdbcUaaAdminUserBootstrap.class);

	public static final String USER_FIELDS = "id,username,password,email,authority,givenName,familyName";

	public static final String INSERT_ADMIN_USER_QUERY = "insert into users (" + USER_FIELDS
			+ ") values (?, ?, ?, ?, 1, ?, ?)";

	public static final String COUNT_USER_QUERY = "select count(id) from users";

	private final JdbcOperations jdbcTemplate;

	private String id = UUID.randomUUID().toString();

	private String username = "admin@localhost";

	private String password = "$2a$10$yHj1jr2NYpGC3wu/BTeFDOnD4Jz3K6ALd6XghGXPTCU4WMxKZuRHu";

	private String email;

	private String givenName = "Admin";

	private String familyName = "User";

	private boolean running = false;

	private boolean autoStartup = true;

	private int phase = 0;

	public JdbcUaaAdminUserBootstrap(JdbcOperations jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	/**
	 * Flag to indicate that we should run on startup (default true).
	 * 
	 * @param autoStartup the auto startup flag to set
	 */
	public void setAutoStartup(boolean autoStartup) {
		this.autoStartup = autoStartup;
	}

	/**
	 * The phase of autostartup to join if auto startup is true. Default 0.
	 * 
	 * @param phase the phase to set
	 */
	public void setPhase(int phase) {
		this.phase = phase;
	}

	/**
	 * The username for the admin user if created (default "admin@localhost").
	 * 
	 * @param username the username to set
	 */
	public void setUsername(String username) {
		this.username = username;
	}

	/**
	 * The password for the admin user if created (default "admin").
	 * 
	 * @param password the password to set
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * The email for the admin user if created (default same as username or <code>username@vcap.me</code>).
	 * 
	 * @param email the email to set
	 */
	public void setEmail(String email) {
		this.email = email;
	}

	/**
	 * The given (first) name for the admin user if created (default "Admin").
	 * 
	 * @param givenName the givenName to set
	 */
	public void setGivenName(String givenName) {
		this.givenName = givenName;
	}

	/**
	 * The family (second) name for the admin user if created (default "User").
	 * 
	 * @param familyName the familyName to set
	 */
	public void setFamilyName(String familyName) {
		this.familyName = familyName;
	}

	@Override
	public void start() {
		running = true;
		email = email == null ? (username.contains("@") ? username : username + "@vcap.me") : email;
		int count = jdbcTemplate.queryForInt(COUNT_USER_QUERY);
		if (count == 0) {
			logger.info(String.format("Inserting admin user with  username=%s, id=%s", username, id));
			jdbcTemplate.update(INSERT_ADMIN_USER_QUERY, id, username, password, email, givenName, familyName);
		}
	}

	@Override
	public void stop() {
	}

	@Override
	public boolean isRunning() {
		return running;
	}

	@Override
	public int getPhase() {
		return phase;
	}

	@Override
	public boolean isAutoStartup() {
		return autoStartup;
	}

	@Override
	public void stop(Runnable callback) {
		running = false;
		callback.run();
	}

}
