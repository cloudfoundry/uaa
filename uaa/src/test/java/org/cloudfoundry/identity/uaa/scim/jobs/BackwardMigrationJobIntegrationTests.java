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

import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.Ignore;
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
public class BackwardMigrationJobIntegrationTests extends AbstractJobIntegrationTests {

	@Autowired
	@Qualifier("userDataBackwardsJob")
	private Job job;

	@Test
	@Ignore // TODO unignore when merging back to master
	public void testJobRuns() throws Exception {
		TestUtils.deleteFrom(cloudControllerDataSource, "users");
		TestUtils.deleteFrom(uaaDataSource, "users");
		JdbcTemplate uaaTemplate = new JdbcTemplate(uaaDataSource);
		uaaTemplate.update("insert into users "
				+ "(id, active, userName, email, password, familyName, givenName, created, lastModified) "
				+ "values (?, ?, ?, ?, ?, ?, ?, ?, ?)", "FOO", true, "uniqua", "uniqua@test.org", "ENCRYPT_ME", "Una",
				"Uniqua", new Date(), new Date());
		JobExecution execution = jobLauncher.run(job, new JobParametersBuilder().addDate("start.date", new Date(0L))
				.toJobParameters());
		assertEquals(BatchStatus.COMPLETED, execution.getStatus());
		Iterator<StepExecution> iterator = execution.getStepExecutions().iterator();
		StepExecution step = iterator.next();
		assertEquals(1, step.getReadCount());
		assertEquals(1, step.getWriteCount());
		JdbcTemplate jdbcTemplate = new JdbcTemplate(cloudControllerDataSource);
		assertEquals(1, jdbcTemplate.queryForInt("select count(*) from users"));
	}
}
