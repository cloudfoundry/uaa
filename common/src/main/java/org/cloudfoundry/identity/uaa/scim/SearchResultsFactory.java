package org.cloudfoundry.identity.uaa.scim;

import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.util.*;

public class SearchResultsFactory {
	private static final Collection<String> schemas = Arrays.asList(ScimUser.SCHEMAS);

	public static <T> SearchResults<Map<String, Object>> buildSearchResultFrom (List<T> input, int startIndex, int count, String[] attributes) {
		return buildSearchResultFrom(input,  startIndex,  count,  attributes, new SimpleAttributeNameMapper(Collections.<String, String> emptyMap()));
	}

	public static <T> SearchResults<Map<String, Object>> buildSearchResultFrom (List<T> input, int startIndex, int count, String[] attributes, AttributeNameMapper mapper) {
		Map<String, Expression> expressions = buildExpressions(attributes, mapper);
		StandardEvaluationContext context = new StandardEvaluationContext();
		Collection<Map<String, Object>> results = new ArrayList<Map<String, Object>>();
		for (T object : input.subList(startIndex - 1, startIndex + count - 1)) {
			Map<String, Object> map = new LinkedHashMap<String, Object>();
			for (String attribute : expressions.keySet()) {
				map.put(attribute, expressions.get(attribute).getValue(context, object));
			}
			results.add(map);
		}

		return new SearchResults<Map<String, Object>>(schemas, results, startIndex, count, input.size());
	}

	private static Map<String, Expression> buildExpressions(String[] attributes, AttributeNameMapper mapper) {
		Map<String, Expression> expressions = new LinkedHashMap<String, Expression>();
		for (String attribute : attributes) {
			String spel = mapper != null ? mapper.mapToInternal(attribute) : attribute;
			Expression expression = new SpelExpressionParser().parseExpression(spel);
			expressions.put(attribute, expression);
		}
		return expressions;
	}

}
