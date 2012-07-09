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

import static szxcvbn.ZxcvbnHelper.*;

import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import szxcvbn.Zxcvbn;

/**
 * Password quality check endpoint.
 *
 * @author Luke Taylor
 */
@Controller
public class PasswordCheckEndpoint {
	private final Integer requiredScore;

	public PasswordCheckEndpoint(int requiredScore) {
		this.requiredScore = requiredScore;
	}

	@RequestMapping(value = "/password", method = RequestMethod.POST)
	@ResponseBody
	public Map<String,Integer> checkPassword(@RequestParam String password) {
		Zxcvbn z = zxcvbn(password);
		Map<String,Integer> result = new HashMap<String,Integer>();
		result.put("score", z.score());
		result.put("required", requiredScore);

		return result;
	}
}
