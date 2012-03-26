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

package org.cloudfoundry.identity.uaa.scim.job;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.batch.item.ItemProcessor;

/**
 * @author Dave Syer
 * 
 */
public class CloudControllerUserItemProcessor implements ItemProcessor<Map<String, ?>, Map<String, ?>> {

	private static Log logger = LogFactory.getLog(CloudControllerUserItemProcessor.class);

	@Override
	public Map<String, ?> process(Map<String, ?> item) throws Exception {

		Map<String, Object> map = new HashMap<String, Object>();

		Integer id = (Integer) item.get("ID");
		map.put("id", UUID.randomUUID().toString());

		// The cloud_controller database seems not to use the active field so the values are not reliable
		// map.put("active", item.get("ACTIVE"));
		
		map.put("created", getDate((Date) item.get("CREATED_AT")));
		map.put("lastModified", getDate((Date) item.get("UPDATED_AT")));

		String email = getEmail(id, (String) item.get("EMAIL"));
		map.put("email", email);
		// UAA has lower-case usernames...
		map.put("userName", email.toLowerCase());

		map.put("password", item.get("CRYPTED_PASSWORD"));

		String[] names = getNames(email);
		map.put("givenName", names[0]);
		map.put("familyName", names[1]);

		return map;

	}

	private String getEmail(Integer id, String email) {
		if (email == null || !email.contains("@")) {
			String msg = "Email invalid for id=" + id + ": " + email;
			logger.info(msg);
			throw new InvalidEmailException(msg);
		}
		return email;
	}

	private Date getDate(Date date) {
		return date == null ? new Date() : date;
	}

	private String[] getNames(String email) {
		String[] split = email.split("@");
		if (split.length == 1) {
			return new String[] { "", email };
		}
		return split;
	}

}
