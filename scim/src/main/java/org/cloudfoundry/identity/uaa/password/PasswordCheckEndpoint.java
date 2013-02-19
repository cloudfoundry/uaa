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

import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordScore;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordScoreCalculator;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Password quality check endpoint.
 *
 * @author Luke Taylor
 */
@Controller
public class PasswordCheckEndpoint {

	private PasswordScoreCalculator scoreCalculator;

	public void setScoreCalculator(PasswordScoreCalculator scoreCalculator) {
		this.scoreCalculator = scoreCalculator;
	}

	@RequestMapping(value = "/password/score", method = RequestMethod.POST)
	@ResponseBody
	public PasswordScore passwordScore(@RequestParam String password, @RequestParam(defaultValue = "") String userData) {
		return scoreCalculator.computeScore(password, StringUtils.commaDelimitedListToStringArray(userData));
	}
}
