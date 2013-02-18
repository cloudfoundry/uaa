package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.rest.AttributeNameMapper;
import org.cloudfoundry.identity.uaa.rest.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.rest.jdbc.SearchQueryConverter;
import org.springframework.util.StringUtils;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ScimSearchQueryConverter implements SearchQueryConverter {

	static final Pattern coPattern = Pattern.compile("(.*?)([a-z0-9_]*) co '(.*?)'([\\s]*.*)", Pattern.CASE_INSENSITIVE);

	static final Pattern swPattern = Pattern.compile("(.*?)([a-z0-9_]*) sw '(.*?)'([\\s]*.*)", Pattern.CASE_INSENSITIVE);

	static final Pattern eqPattern = Pattern.compile("(.*?)([a-z0-9_]*) eq '(.*?)'([\\s]*.*)", Pattern.CASE_INSENSITIVE);

	static final Pattern boPattern = Pattern.compile("(.*?)([a-z0-9_]*) eq (true|false)([\\s]*.*)", Pattern.CASE_INSENSITIVE);

	static final Pattern metaPattern = Pattern.compile("(.*?)meta\\.([a-z0-9_]*) (\\S) '(.*?)'([\\s]*.*)", Pattern.CASE_INSENSITIVE);

	static final Pattern prPattern = Pattern.compile(" pr([\\s]*)", Pattern.CASE_INSENSITIVE);

	static final Pattern gtPattern = Pattern.compile(" gt ", Pattern.CASE_INSENSITIVE);

	static final Pattern gePattern = Pattern.compile(" ge ", Pattern.CASE_INSENSITIVE);

	static final Pattern ltPattern = Pattern.compile(" lt ", Pattern.CASE_INSENSITIVE);

	static final Pattern lePattern = Pattern.compile(" le ", Pattern.CASE_INSENSITIVE);

	private static final DateFormat TIMESTAMP_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

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

		where = makeCaseInsensitive(where, coPattern, "%slower(%s) like :?%s", "%%%s%%", values);
		where = makeCaseInsensitive(where, swPattern, "%slower(%s) like :?%s", "%s%%", values);
		where = makeCaseInsensitive(where, eqPattern, "%slower(%s) = :?%s", "%s", values);
		where = makeBooleans(where, boPattern, "%s%s = :?%s", values);
		where = prPattern.matcher(where).replaceAll(" is not null$1");
		where = gtPattern.matcher(where).replaceAll(" > ");
		where = gePattern.matcher(where).replaceAll(" >= ");
		where = ltPattern.matcher(where).replaceAll(" < ");
		where = lePattern.matcher(where).replaceAll(" <= ");
		// This will catch equality of number literals
		where = where.replaceAll(" eq ", " = ");
		where = makeTimestamps(where, metaPattern, "%s%s %s :?%s", values);
		where = where.replaceAll("meta\\.", "");

		return where;
	}

	private String makeTimestamps(String where, Pattern pattern, String template, Map<String, Object> values) {
		String output = where;
		Matcher matcher = pattern.matcher(output);
		int count = values.size();
		while (matcher.matches()) {
			String property = matcher.group(2);
			Object value = matcher.group(4);
			if (property.equals("created") || property.equals("lastModified")) {
				try {
					value = TIMESTAMP_FORMAT.parse((String) value);
				}
				catch (ParseException e) {
					// ignore
				}
			}
			values.put("value" + count, value);
			String query = template.replace("?", "value" + count);
			output = matcher.replaceFirst(String.format(query, matcher.group(1), property, matcher.group(3),
															   matcher.group(5)));
			matcher = pattern.matcher(output);
			count++;
		}
		return output;
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

	private String makeBooleans(String where, Pattern pattern, String template, Map<String, Object> values) {
		String output = where;
		Matcher matcher = pattern.matcher(output);
		int count = values.size();
		while (matcher.matches()) {
			values.put("value" + count, Boolean.valueOf(matcher.group(3).toLowerCase()));
			String query = template.replace("?", "value" + count);
			output = matcher.replaceFirst(String.format(query, matcher.group(1), matcher.group(2), matcher.group(4)));
			matcher = pattern.matcher(output);
			count++;
		}
		return output;
	}
}
