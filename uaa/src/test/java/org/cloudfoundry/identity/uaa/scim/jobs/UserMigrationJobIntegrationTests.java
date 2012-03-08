/**
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

package org.cloudfoundry.identity.uaa.scim.jobs;

import static org.junit.Assert.assertEquals;

import java.util.Date;
import java.util.Iterator;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.ParentContextLoader;
import org.cloudfoundry.identity.uaa.TestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.batch.core.BatchStatus;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.JobParameters;
import org.springframework.batch.core.StepExecution;
import org.springframework.batch.core.launch.support.SimpleJobLauncher;
import org.springframework.batch.core.repository.JobRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Dave Syer
 * 
 */
@ContextConfiguration(locations = { "file:./src/main/webapp/WEB-INF/applicationContext.xml",
		"file:./src/main/webapp/WEB-INF/batch-servlet.xml", "classpath*:/META-INF/spring/batch/jobs/jobs.xml" }, loader = ParentContextLoader.class)
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = { "", "test,postgresql", "hsqldb" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class UserMigrationJobIntegrationTests {

	private SimpleJobLauncher jobLauncher;

	@Autowired
	public void setJobRepository(JobRepository jobRepository) throws Exception {
		SimpleJobLauncher jobLauncher = new SimpleJobLauncher();
		jobLauncher.setJobRepository(jobRepository);
		jobLauncher.afterPropertiesSet();
		this.jobLauncher = jobLauncher;
	}

	@Autowired
	@Qualifier("userDataMigrationJob")
	private Job job;

	@Autowired
	@Qualifier("cloudControllerDataSource")
	private DataSource cloudControllerDataSource;

	@Autowired
	@Qualifier("uaaDataSource")
	private DataSource uaaDataSource;

	@Before
	public void setUpData() throws Exception {
		TestUtils.runScript(cloudControllerDataSource, "cloud-controller-schema");
		TestUtils.runScript(uaaDataSource, "schema");
		new JdbcTemplate(cloudControllerDataSource)
				.update("insert into users (id, active, email, crypted_password, created_at, updated_at) values (?, ?, ?, ?, ?, ?)",
						0, true, "marissa@test.org", "ENCRYPT_ME", new Date(), new Date());
		new JdbcTemplate(cloudControllerDataSource)
				.update("insert into users (id, active, email, crypted_password, created_at, updated_at) values (?, ?, ?, ?, ?, ?)",
						1, true, "vcap_tester@vmware.com", "ENCRYPT_ME", new Date(), new Date());
	}

	@After
	public void clearUp() {
		new JdbcTemplate(uaaDataSource).update("delete from users");
	}

	@Test
	public void testJobRuns() throws Exception {
		JobExecution execution = jobLauncher.run(job, new JobParameters());
		assertEquals(BatchStatus.COMPLETED, execution.getStatus());
		Iterator<StepExecution> iterator = execution.getStepExecutions().iterator();
		assertEquals(2, iterator.next().getWriteCount());
		assertEquals(1, iterator.next().getWriteCount());
	}

}
