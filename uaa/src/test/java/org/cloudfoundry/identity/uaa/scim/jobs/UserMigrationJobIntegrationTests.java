/**
 * Cloud Foundry 2012.02.03 Beta Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 * 
 * This product is licensed to you under the Apache License, Version 2.0 (the "License"). You may not use this product
 * except in compliance with the License.
 * 
 * This product includes a number of subcomponents with separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE file.
 */

package org.cloudfoundry.identity.uaa.scim.jobs;

import static org.junit.Assert.assertEquals;

import java.util.Date;
import java.util.Iterator;

import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.junit.Test;
import org.springframework.batch.core.BatchStatus;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.core.StepExecution;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * @author Dave Syer
 * 
 */
public class UserMigrationJobIntegrationTests extends AbstractJobIntegrationTests {

	@Autowired
	@Qualifier("userDataMigrationJob")
	private Job job;

	@Test
	public void testJobRuns() throws Exception {
		new JdbcTemplate(cloudControllerDataSource)
		.update("insert into users (id, active, email, crypted_password, created_at, updated_at) values (?, ?, ?, ?, ?, ?)",
				4, true, "invalid", "ENCRYPT_ME", new Date(), new Date());
		JobExecution execution = jobLauncher.run(job,
				new JobParametersBuilder().addString("users", "marissa@test.org,vcap_tester@vmware.com")
						.toJobParameters());
		assertEquals(BatchStatus.COMPLETED, execution.getStatus());
		Iterator<StepExecution> iterator = execution.getStepExecutions().iterator();
		assertEquals(3, iterator.next().getWriteCount());
		assertEquals(2, iterator.next().getWriteCount());
		JdbcTemplate jdbcTemplate = new JdbcTemplate(uaaDataSource);
		assertEquals(3, jdbcTemplate.queryForInt("select count(*) from users"));
		assertEquals(
				2,
				jdbcTemplate.queryForInt("select count(*) from users where authority=?",
						UaaAuthority.ROLE_ADMIN.value()));
	}

}
