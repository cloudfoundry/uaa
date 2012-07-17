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

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

/**
 * @author Luke Taylor
 */
public class PasswordCheckEndpointTests {

	@Test
	public void checkReturnsExpectedScore() throws Exception {
		PasswordCheckEndpoint pc = new PasswordCheckEndpoint();
		pc.setScoreCalculator(new ZxcvbnPasswordScoreCalculator(5));

		PasswordScore score = pc.passwordScore("password1");

		assertTrue(score.getScore() == 0);
		assertFalse(score.isAcceptable());

		score = pc.passwordScore("thisisasufficientlylongstring");
		assertTrue(score.isAcceptable());
	}
}
