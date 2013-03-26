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
package org.cloudfoundry.identity.uaa.rest.jdbc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.rest.jdbc.JdbcPagingList;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.ColumnMapRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = { "", "test,postgresql", "hsqldb", "test,mysql" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcPagingListTests {

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private List<Map<String, Object>> list;

	@Before
	public void createDatasource() throws Exception {

		template = new JdbcTemplate(dataSource);
		template.execute("create table foo (id integer primary key, name varchar(10) not null)");
		template.execute("insert into foo (id, name) values (0, 'foo')");
		template.execute("insert into foo (id, name) values (1, 'bar')");
		template.execute("insert into foo (id, name) values (2, 'baz')");
		template.execute("insert into foo (id, name) values (3, 'zab')");
		template.execute("insert into foo (id, name) values (4, 'rab')");

	}

	@After
	public void clear() throws Exception {
		template.execute("drop table foo");
	}

	@Test
	public void testIterationOverPages() throws Exception {
		list = new JdbcPagingList<Map<String, Object>>(template, "SELECT * from foo where id>=:id",
				Collections.<String, Object> singletonMap("id", 0), new ColumnMapRowMapper(), 3);
		assertEquals(5, list.size());
		Set<String> names = new HashSet<String>();
		for (Map<String, Object> map : list) {
			String name = (String) map.get("name");
			assertNotNull(name);
			names.add(name);
		}
		assertEquals(5, names.size());
		names = new HashSet<String>();
		for (Map<String, Object> map : list) {
			String name = (String) map.get("name");
			assertNotNull(name);
			names.add(name);
		}
		assertEquals(5, names.size());
	}

	@Test
	public void testIterationWithDeletedElements() throws Exception {
		list = new JdbcPagingList<Map<String, Object>>(template, "SELECT * from foo where id>=:id",
				Collections.<String, Object> singletonMap("id", 0), new ColumnMapRowMapper(), 3);
		template.update("DELETE from foo where id>3");
		assertEquals(5, list.size());
		Set<String> names = new HashSet<String>();
		for (Map<String, Object> map : list) {
			String name = (String) map.get("name");
			assertNotNull(name);
			names.add(name);
		}
		assertEquals(4, names.size());
	}

	@Test
	public void testOrderBy() throws Exception {
		list = new JdbcPagingList<Map<String, Object>>(template, "SELECT * from foo order by id asc",
				Collections.<String, Object> singletonMap("id", 0), new ColumnMapRowMapper(), 3);
		assertEquals(5, list.size());
		Set<String> names = new HashSet<String>();
		for (Map<String, Object> map : list) {
			String name = (String) map.get("name");
			assertNotNull(name);
			names.add(name);
		}
		assertEquals(5, names.size());
	}

	@Test
	public void testJumpOverPages() throws Exception {
		list = new JdbcPagingList<Map<String, Object>>(template, "SELECT * from foo", new ColumnMapRowMapper(), 3);
		Map<String, Object> map = list.get(3);
		assertNotNull(map.get("name"));
	}

	@Test
	public void testIterationOverSubList() throws Exception {
		list = new JdbcPagingList<Map<String, Object>>(template, "SELECT * from foo", new ColumnMapRowMapper(), 3);
		list = list.subList(1, 4);
		assertEquals(3, list.size());
		int count = 0;
		for (Map<String, Object> map : list) {
			count++;
			assertNotNull(map.get("name"));
		}
		assertEquals(3, count);
	}

	@Test
	public void testIterationOverSubListWithSameSize() throws Exception {
		list = new JdbcPagingList<Map<String, Object>>(template, "SELECT * from foo", new ColumnMapRowMapper(), 3);
		list = list.subList(0, 5);
		assertEquals(5, list.size());
		int count = 0;
		for (Map<String, Object> map : list) {
			count++;
			assertNotNull(map.get("name"));
		}
		assertEquals(5, count);
	}

	@Test(expected=IndexOutOfBoundsException.class)
	public void testSubListExtendsBeyondSize() throws Exception {
		list = new JdbcPagingList<Map<String, Object>>(template, "SELECT * from foo", new ColumnMapRowMapper(), 3);
		list.subList(1, 40);
	}

	@Test
	public void testSubListFromDeletedElements() throws Exception {
		list = new JdbcPagingList<Map<String, Object>>(template, "SELECT * from foo", new ColumnMapRowMapper(), 3);
		template.update("DELETE from foo where id>3");
		list = list.subList(1, list.size());
		assertEquals(4, list.size());
		int count = 0;
		for (Map<String, Object> map : list) {
			count++;
			assertNotNull(map.get("name"));
		}
		assertEquals(3, count); // count is less than original size estimate
	}

}
