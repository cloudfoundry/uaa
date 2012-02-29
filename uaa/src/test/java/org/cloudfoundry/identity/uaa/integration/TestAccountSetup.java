/**
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
package org.cloudfoundry.identity.uaa.integration;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.rules.TestWatchman;
import org.junit.runners.model.FrameworkMethod;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.codec.Base64;

/**
 * @author Dave Syer
 * 
 */
public class TestAccountSetup extends TestWatchman {

	private static final Log logger = LogFactory.getLog(TestAccountSetup.class);

	private Environment environment = TestProfileEnvironment.getEnvironment();

	private LegacyTokenServer tokenServer;

	private final String legacyProfileName;

	private TestAccountSetup() {
		this(null);
	}

	private TestAccountSetup(String legacyProfileName) {
		this.legacyProfileName = legacyProfileName;
		// The token server has to startup early in case the user account information is needed by another rule that
		// wants the server to be running...
		tokenServer = null;
		if (isLegacy()) {
			tokenServer = new LegacyTokenServer();
			try {
				logger.debug("Starting legacy token server");
				tokenServer.init();
			}
			catch (Exception e) {
				logger.error("Could not start legacy token server", e);
				Assert.fail("Could not start legacy token server");
			}
		}
	}

	public static TestAccountSetup standard() {
		return new TestAccountSetup();
	}

	public static TestAccountSetup withLegacyTokenServerForProfile(String legacyProfileName) {
		TestAccountSetup testAccountSetup = new TestAccountSetup(legacyProfileName);
		return testAccountSetup;
	}

	public String getUserName() {
		return environment.getProperty("uaa.test.username", "marissa");
	}

	public String getPassword() {
		return environment.getProperty("uaa.test.password", "koala");
	}

	public String getEmail() {
		return environment.getProperty("uaa.test.email", "marissa@test.org");
	}

	@Override
	public void finished(FrameworkMethod method) {
		if (tokenServer != null) {
			try {
				tokenServer.close();
			}
			catch (Exception e) {
				logger.error("Could not stop legacy token server", e);
			}
		}
	}

	/**
	 * @return true if the legacy Spring profile is enabled on the server
	 */
	public boolean isProfileActive(String profile) {
		List<String> profiles = Arrays.asList(environment.getActiveProfiles());
		logger.debug(String.format("Checking for %s profile in: [%s]", profile, environment));
		return profile != null && profiles.contains(profile);
	}

	/**
	 * @return true if the legacy Spring profile is enabled on the server
	 */
	public boolean isLegacy() {
		return isProfileActive(legacyProfileName);
	}

	/**
	 * @return
	 */
	public String getVarzAuthorizationHeader() {
		return String.format("Basic %s", new String(Base64.encode("varz:varzclientsecret".getBytes())));
	}

}
