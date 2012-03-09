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
public class UserSyncJobIntegrationTests extends AbstractJobIntegrationTests {

	@Autowired
	@Qualifier("userDataSyncJob")
	private Job job;

	public void setUpModifiedUaaData(Date modified) throws Exception {
		JdbcTemplate template = new JdbcTemplate(uaaDataSource);
		template.update(
				"insert into users (id, version, active, email, password, created, lastModified, userName, givenName, familyName) "
						+ "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", "00", 0, true, "marissa@test.org", "ENCRYPT_ME",
				new Date(), modified, "marissa@test.org", "Marissa", "Koala");
		template.update(
				"insert into users (id, version, active, email, password, created, lastModified, userName, givenName, familyName) "
						+ "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", "01", 0, true, "vcap_tester@vmware.com",
				"ENCRYPT_ME", new Date(), modified, "vcap_tester@vmware.com", "Vcap", "Tester");
		template.update(
				"insert into users (id, version, active, email, password, created, lastModified, userName, givenName, familyName) "
						+ "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", "02", 0, true, "dale@test.org", "ENCRYPT_ME",
				new Date(), modified, "dale@test.org", "Dale", "Olds");
	}

	@Test
	public void testJobRunsWithFilters() throws Exception {
		Date dateInTheFuture = new Date(System.currentTimeMillis() + 10000);
		setUpModifiedUaaData(dateInTheFuture);
		JobExecution execution = jobLauncher.run(job,
				new JobParametersBuilder().addDate("start.date", new Date(System.currentTimeMillis() - 100000))
						.toJobParameters());
		assertEquals(BatchStatus.COMPLETED, execution.getStatus());
		StepExecution stepExecution = execution.getStepExecutions().iterator().next();
		assertEquals(3, stepExecution.getReadCount());
		assertEquals(3, stepExecution.getFilterCount());
		assertEquals(0, stepExecution.getWriteCount());
	}

	@Test
	public void testJobRunsWithNoFilters() throws Exception {
		Date dateInThePast = new Date(System.currentTimeMillis() - 10000);
		setUpModifiedUaaData(dateInThePast);
		JobExecution execution = jobLauncher.run(job,
				new JobParametersBuilder().addDate("start.date", new Date(System.currentTimeMillis() - 100000))
						.toJobParameters());
		assertEquals(BatchStatus.COMPLETED, execution.getStatus());
		StepExecution stepExecution = execution.getStepExecutions().iterator().next();
		assertEquals(3, stepExecution.getReadCount());
		assertEquals(0, stepExecution.getFilterCount());
		// No records are updated, but the filter count is always write - read
		assertEquals(3, stepExecution.getWriteCount());
	}

}
