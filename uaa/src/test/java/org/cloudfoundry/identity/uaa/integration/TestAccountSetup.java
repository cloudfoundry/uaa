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
	public boolean isLegacy() {
		List<String> profiles = Arrays.asList(environment.getActiveProfiles());
		logger.debug(String.format("Checking for %s profile in: [%s]", legacyProfileName, environment));
		return legacyProfileName != null && profiles.contains(legacyProfileName);
	}

	/**
	 * @return
	 */
	public String getVarzAuthorizationHeader() {
		return String.format("Basic %s", new String(Base64.encode("varz:varzclientsecret".getBytes())));
	}

}
