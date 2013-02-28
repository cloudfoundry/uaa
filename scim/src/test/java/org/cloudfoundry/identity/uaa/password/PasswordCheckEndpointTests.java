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

package org.cloudfoundry.identity.uaa.password;

import static junit.framework.Assert.assertTrue;

import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordScore;
import org.junit.Test;

/**
 * @author Luke Taylor
 */
public class PasswordCheckEndpointTests {

	@Test
	public void checkReturnsExpectedScore() throws Exception {
		PasswordCheckEndpoint pc = new PasswordCheckEndpoint();
		pc.setScoreCalculator(new ZxcvbnPasswordScoreCalculator(5));

		PasswordScore score = pc.passwordScore("password1", "");

		assertTrue(score.getScore() == 0);

		score = pc.passwordScore("thisisasufficientlylongstring", "");
		assertTrue(score.getScore() >= score.getRequiredScore());
	}
}
