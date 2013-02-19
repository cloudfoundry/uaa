/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2013] VMware, Inc. All Rights Reserved.
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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.cloudfoundry.identity.uaa.rest.AttributeNameMapper;
import org.cloudfoundry.identity.uaa.rest.SimpleAttributeNameMapper;
import org.springframework.util.StringUtils;

public class SimpleSearchQueryConverter implements SearchQueryConverter {

	static final Pattern equalsPattern = Pattern.compile("(.*?)([a-z0-9_]*) eq '(.*?)'([\\s]*.*)", Pattern.CASE_INSENSITIVE);

	static final Pattern existsPattern = Pattern.compile(" pr([\\s]*)", Pattern.CASE_INSENSITIVE);

	private AttributeNameMapper mapper = new SimpleAttributeNameMapper(Collections.<String, String> emptyMap());

	public void setAttributeNameMapper(AttributeNameMapper mapper) {
		this.mapper = mapper;
	}

	@Override
	public ProcessedFilter convert(String filter, String sortBy, boolean ascending) {
		return convert(filter, sortBy, ascending, mapper);
	}

	@Override
	public ProcessedFilter convert(String filter, String sortBy, boolean ascending, AttributeNameMapper mapper) {
		Map<String, Object> values = new HashMap<String, Object>();
		String where = StringUtils.hasText(filter) ? getWhereClause(filter, sortBy, ascending, values, mapper) : null;
		return new ProcessedFilter(where, values);
	}

	private String getWhereClause (String filter, String sortBy, boolean ascending, Map<String, Object> values, AttributeNameMapper mapper) {

		// Single quotes for literals
		String where = filter.replaceAll("\"", "'");

		if (sortBy != null) {
			// Need to add "asc" or "desc" explicitly to ensure that the pattern splitting below works
			where = where + " order by " + sortBy + (ascending ? " asc" : " desc");
		}

		where = mapper.mapToInternal(where);

		where = makeCaseInsensitive(where, equalsPattern, "%slower(%s) = :?%s", "%s", values);
		where = existsPattern.matcher(where).replaceAll(" is not null$1");
		// This will catch equality of number literals
		where = where.replaceAll(" == ", " = ");

		return where;
	}

	private String makeCaseInsensitive(String where, Pattern pattern, String template, String valueTemplate,
									   Map<String, Object> values) {
		String output = where;
		Matcher matcher = pattern.matcher(output);
		int count = values.size();
		while (matcher.matches()) {
			values.put("value" + count, String.format(valueTemplate, matcher.group(3).toLowerCase()));
			String query = template.replace("?", "value" + count);
			output = matcher.replaceFirst(String.format(query, matcher.group(1), matcher.group(2), matcher.group(4)));
			matcher = pattern.matcher(output);
			count++;
		}
		return output;
	}

}
