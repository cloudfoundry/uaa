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
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.StringUtils;

/**
 * Tasklet to change users' granted authorities.
 * 
 * @author Dave Syer
 * 
 */
public class AdminUsersTasklet implements Tasklet {

	private JdbcOperations jdbcTemplate;

	private Collection<String> admins = Collections.emptySet();

	private UaaAuthority authority = UaaAuthority.UAA_ADMIN;

	public void setDataSource(DataSource dataSource) {
		jdbcTemplate = new JdbcTemplate(dataSource);
	}

	public void setAdmins(Collection<String> admins) {
		this.admins = new HashSet<String>(admins);
	}

	public void setAuthority(UaaAuthority authority) {
		this.authority = authority;
	}

	@Override
	public RepeatStatus execute(StepContribution contribution, ChunkContext chunkContext) throws Exception {
		String authorities = StringUtils.collectionToCommaDelimitedString(AuthorityUtils
				.authorityListToSet(authority == UaaAuthority.UAA_USER ? UaaAuthority.USER_AUTHORITIES
						: UaaAuthority.ADMIN_AUTHORITIES));
		for (String user : admins) {
			int updated = jdbcTemplate.update("update users set authorities=? where userName=?", authorities, user);
			contribution.incrementWriteCount(updated);
		}
		return RepeatStatus.FINISHED;
	}

}
