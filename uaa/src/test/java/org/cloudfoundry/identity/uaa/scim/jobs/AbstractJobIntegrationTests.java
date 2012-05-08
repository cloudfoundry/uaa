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

import java.util.Date;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.ParentContextLoader;
import org.cloudfoundry.identity.uaa.TestUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
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
@IfProfileValue(name = "spring.profiles.active", values = { "", "test,postgresql", "hsqldb", "empty,postgresql" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public abstract class AbstractJobIntegrationTests {

	protected SimpleJobLauncher jobLauncher;

	@BeforeClass
	public static void setUpDatabaseUrl() {
		// Switch the database URL for these tests so that any stale connections from other places don't muck things up
		if (System.getProperty("spring.profiles.active", "").contains("hsqldb")) {
			System.setProperty("batch.jdbc.url", "jdbc:hsqldb:mem:batchtest;sql.enforce_strict_size=true");
		}
	}

	@AfterClass
	public static void cleanUpDatabaseUrl() {
		System.clearProperty("batch.jdbc.url");
	}

	@Autowired
	public void setJobRepository(JobRepository jobRepository) throws Exception {
		SimpleJobLauncher jobLauncher = new SimpleJobLauncher();
		jobLauncher.setJobRepository(jobRepository);
		jobLauncher.afterPropertiesSet();
		this.jobLauncher = jobLauncher;
	}

	@Autowired
	@Qualifier("cloudControllerDataSource")
	protected DataSource cloudControllerDataSource;

	@Autowired
	@Qualifier("uaaDataSource")
	protected DataSource uaaDataSource;

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
		new JdbcTemplate(cloudControllerDataSource)
				.update("insert into users (id, active, email, crypted_password, created_at, updated_at) values (?, ?, ?, ?, ?, ?)",
						2, true, "dale@test.org", "ENCRYPT_ME", new Date(), new Date());
	}

	@After
	public void clearUp() {
		new JdbcTemplate(cloudControllerDataSource).update("delete from users");
		new JdbcTemplate(uaaDataSource).update("delete from users");
	}

}
