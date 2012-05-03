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
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Item processor that transforms Uaa user records into Cloud Controller user records.
 * 
 * @author Dave Syer
 * 
 */
public class UaaUserItemProcessor implements ItemProcessor<Map<String, ?>, Map<String, ?>> {

	private static Log logger = LogFactory.getLog(UaaUserItemProcessor.class);

	private boolean filterExisting = false;

	private int count = 0;

	private JdbcOperations jdbcTemplate;

	public void setDataSource(DataSource dataSource) {
		jdbcTemplate = new JdbcTemplate(dataSource);
	}

	/**
	 * Filter out records where there is already an account in the target database.
	 * 
	 * @param filterExisting the flag to set
	 */
	public void setFilterExisting(boolean filterExisting) {
		this.filterExisting = filterExisting;
	}

	@Override
	public Map<String, ?> process(Map<String, ?> item) throws Exception {

		Map<String, Object> map = new HashMap<String, Object>();

		map.put("CREATED_AT", getDate((Date) item.get("created")));
		map.put("UPDATED_AT", getDate((Date) item.get("lastModified")));

		String email = getEmail((String) item.get("email"));
		map.put("EMAIL", email);

		map.put("CRYPTED_PASSWORD", item.get("password"));

		if (filterExisting) {
			if (jdbcTemplate.queryForInt("select count(id) from users where email=?", email) > 0) {
				// Filter this item
				return null;
			}
		}

		count++;
		if (count <= 1000) {
			logger.debug("User account processed (" + count + "): " + map);
			if (count == 1000) {
				logger.debug("Logging of user accounts processed stopped");
			}
		}

		return map;

	}

	private String getEmail(String email) {
		if (email == null || !email.contains("@")) {
			String msg = "Email invalid for: " + email;
			logger.info(msg);
			throw new InvalidEmailException(msg);
		}
		return email;
	}

	private Date getDate(Date date) {
		return date == null ? new Date() : date;
	}

}
