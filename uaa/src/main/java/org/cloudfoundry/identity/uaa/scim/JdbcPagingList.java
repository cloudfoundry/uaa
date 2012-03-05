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

package org.cloudfoundry.identity.uaa.scim;

import java.util.AbstractList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * @author Dave Syer
 * 
 */
public class JdbcPagingList<E> extends AbstractList<E> {

	private final int size;

	private int start = 0;

	private List<E> current;

	private final int pageSize;

	private final RowMapper<E> mapper;

	private final Map<String, ?> args;

	private final String sql;

	private final NamedParameterJdbcTemplate parameterJdbcTemplate;

	public JdbcPagingList(JdbcTemplate jdbTemplate, String sql, RowMapper<E> mapper, int pageSize) {
		this(jdbTemplate, sql, Collections.<String, Object> emptyMap(), mapper, pageSize);
	}

	public JdbcPagingList(JdbcTemplate jdbcTemplate, String sql, Map<String, ?> args, RowMapper<E> mapper, int pageSize) {
		this.parameterJdbcTemplate = new NamedParameterJdbcTemplate(jdbcTemplate);
		this.sql = sql;
		this.args = args;
		this.mapper = mapper;
		this.size = parameterJdbcTemplate.queryForInt(getCountSql(sql), args);
		this.pageSize = pageSize;
	}

	@Override
	public E get(int index) {
		if (index >= size) {
			throw new ArrayIndexOutOfBoundsException(index);
		}
		if (current == null || index - start >= pageSize) {
			current = parameterJdbcTemplate.query(getLimitSql(sql, index, pageSize), args, mapper);
			start = index;
		}
		return current.get(index - start);
	}

	@Override
	public List<E> subList(int fromIndex, int toIndex) {
		int end = toIndex > size ? size : toIndex;
		return super.subList(fromIndex, end);
	}

	private String getLimitSql(String sql, int index, int size) {
		return sql + " limit " + size + " offset " + index;
	}

	private String getCountSql(String sql) {
		String result = sql.toLowerCase().replaceAll("select (.*?) from (.*)", "select count(*) from $2");
		if (result.contains("order by")) {
			result = result.substring(0, result.lastIndexOf("order by"));
		}
		return result;
	}

	@Override
	public int size() {
		return this.size;
	}

}
