/*
 * Cloud Foundry 2012.02.03 Beta Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 * 
 * This product is licensed to you under the Apache License, Version 2.0 (the "License"). You may not use this product
 * except in compliance with the License.
 * 
 * This product includes a number of subcomponents with separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE file.
 */

package org.cloudfoundry.identity.uaa.rest.jdbc;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.AbstractList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * <p>
 * List implementation backed by a database query, allowing iteration and sublist operations without pulling the wole
 * dataset into memory.
 * </p>
 * 
 * <p>
 * Not thread safe.
 * </p>
 * 
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
		this(new NamedParameterJdbcTemplate(jdbcTemplate), sql, args, mapper, pageSize);
	}

	public JdbcPagingList(NamedParameterJdbcTemplate jdbcTemplate, String sql, Map<String, ?> args, RowMapper<E> mapper, int pageSize) {
		this.parameterJdbcTemplate = jdbcTemplate;
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
		if (current == null || index - start >= pageSize || index < start) {
			current = parameterJdbcTemplate.query(getLimitSql(sql, index, pageSize), args, mapper);
			start = index;
		}
		return current.get(index - start);
	}

	@Override
	public Iterator<E> iterator() {
		return new SafeIterator<E>(super.iterator());
	}

	@Override
	public List<E> subList(int fromIndex, int toIndex) {
		if(fromIndex < 0 || toIndex > size || fromIndex > toIndex) {
			throw new IndexOutOfBoundsException("The indexes provided are outside the bounds of this list.");
		}
		return new SafeIteratorList<E>(super.subList(fromIndex, toIndex));
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

	/**
	 * <p>
	 * A list whose iterators are safe from changes in the underlying list. The size is not always accurate if the
	 * underlying list changes, but the iterator will never say it has more elements and then fail when iterated.
	 * </p>
	 * 
	 * <p>
	 * Not thread safe.
	 * </p>
	 * 
	 * @author Dave Syer
	 * 
	 * @param <T> the element type
	 */
	private static class SafeIteratorList<T> extends AbstractList<T> {

		private final List<T> list;

		public SafeIteratorList(List<T> list) {
			this.list = list;
		}

		@Override
		public Iterator<T> iterator() {
			return new SafeIterator<T>(super.iterator());
		}

		@Override
		public T get(int index) {
			return list.get(index);
		}

		@Override
		public int size() {
			return list.size();
		}
	}

	private static class SafeIterator<T> implements Iterator<T> {

		private final Iterator<T> iterator;

		private boolean polled = false;

		private boolean hasNext = false;

		private T next;

		public SafeIterator(Iterator<T> iterator) {
			this.iterator = iterator;
		}

		@Override
		public boolean hasNext() {
			if (!polled) {
				polled = true;
				try {
					next = iterator.next();
					hasNext = true;
					return true;
				} catch (NoSuchElementException e) {
					hasNext = false;
					return false;
				}
			}
			return hasNext;
		}

		@Override
		public T next() {
			if (hasNext()) {
				polled = false;
				return next;
			}
			throw new NoSuchElementException();
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException("Not supported: readonly interator");
		}
	}
}
