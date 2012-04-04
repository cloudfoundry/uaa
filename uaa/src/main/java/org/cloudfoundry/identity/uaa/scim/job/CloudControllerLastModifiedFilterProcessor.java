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

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * @author Dave Syer
 * 
 */
public class CloudControllerLastModifiedFilterProcessor implements ItemProcessor<Map<String, ?>, Map<String, ?>> {

	private static Log logger = LogFactory.getLog(CloudControllerLastModifiedFilterProcessor.class);

	private JdbcOperations jdbcTemplate;
	
	public void setDataSource(DataSource dataSource) {
		jdbcTemplate = new JdbcTemplate(dataSource);
	}
	
	@Override
	public Map<String, ?> process(Map<String, ?> item) throws Exception {

		Map<String, Object> map = new HashMap<String, Object>();

		Integer id = (Integer) item.get("ID");		
		map.put("lastModified", new Date());

		String email = getEmail(id, (String) item.get("EMAIL"));
		// UAA has lower-case usernames...
		String userName = email.toLowerCase();
		map.put("userName", userName);
		map.put("email", email);

		Map<String, Object> target;
		try {
			target = jdbcTemplate.queryForMap("select * from users where userName=?", userName);
		} catch (EmptyResultDataAccessException e) {
			// skip this record
			return null;
		}
		
		if (isTargetModifiedMoreRecently(item, target)) {
			logger.info("Target is modified more recently than source for: " + target);
			return null;
		}
		
		map.put("password", item.get("CRYPTED_PASSWORD"));
		map.put("version", getVersion(target) + 1);

		return map;

	}

	private boolean isTargetModifiedMoreRecently(Map<String, ?> source, Map<String, ?> target) {
		Date targetModified = (Date) target.get("lastModified");
		Date sourceModified = (Date) source.get("updated_at");
		return targetModified.compareTo(sourceModified)>=0;
	}

	private long getVersion(Map<String, Object> target) {
		return (Long) target.get("version");
	}

	private String getEmail(Integer id, String email) {
		if (email == null || !email.contains("@")) {
			String msg = "Email invalid for id=" + id + ": " + email;
			logger.info(msg);
			throw new InvalidEmailException(msg);
		}
		return email;
	}

}
