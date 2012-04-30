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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.batch.core.StepContribution;
import org.springframework.batch.core.scope.context.ChunkContext;
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.repeat.RepeatStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Tasklet to change users' granted authorities.
 * 
 * @author Dave Syer
 *
 */
public class AdminUsersTasklet implements Tasklet {
	
	private JdbcOperations jdbcTemplate;
	
	private Collection<String> admins = Collections.emptySet();

	private int authority = 1;
	
	public void setDataSource(DataSource dataSource) {
		jdbcTemplate = new JdbcTemplate(dataSource);
	}
	
	public void setAdmins(Collection<String> admins) {
		this.admins = new HashSet<String>(admins);
	}
	
	public void setAuthority(UaaAuthority authority) {
		this.authority = authority.value();
	}

	@Override
	public RepeatStatus execute(StepContribution contribution, ChunkContext chunkContext) throws Exception {
		for (String user : admins) {
			int updated = jdbcTemplate.update("update users set authority=? where userName=?", authority , user);
			contribution.incrementWriteCount(updated);
		}
		return RepeatStatus.FINISHED;
	}

}
