/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.resources;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.util.Assert;

public class SearchResultsFactory {
    public static <T> SearchResults<Map<String, Object>> cropAndBuildSearchResultFrom(
        List<T> input,
        int startIndex,
        int count,
        int total,
        String[] attributes,
        List<String> schemas)  {

        if (startIndex <= 0) {
            //must start with 1
            startIndex = 1;
        }
        if ( (startIndex -1) >= input.size() ) {
            //start index is past the last result
            count = 0;
        }
        if ( ((startIndex-1)+count) >= input.size()) {
            //we're past the last result
            count = input.size() - (startIndex - 1);
        }

        input = count>0 ? input.subList(startIndex-1, startIndex-1+count) : Collections.<T>emptyList();

        return buildSearchResultFrom(
            input,
            startIndex,
            count,
            total,
            attributes,
            new SimpleAttributeNameMapper(Collections.<String, String> emptyMap()),
            schemas);

    }


    public static <T> SearchResults<Map<String, Object>> buildSearchResultFrom(
        List<T> input,
        int startIndex,
        int count,
        int total,
        String[] attributes,
        List<String> schemas)  {

        return buildSearchResultFrom(
            input,
            startIndex,
            count,
            total,
            attributes,
            new SimpleAttributeNameMapper(Collections.<String, String> emptyMap()),
            schemas);

    }

    public static <T> SearchResults<Map<String, Object>> buildSearchResultFrom(
        List<T> input,
        int startIndex,
        int count,
        int total,
        String[] attributes,
        AttributeNameMapper mapper,
        List<String> schemas) {

        Assert.state(input.size() <= count,
                        "Cannot build search results from parent list. Use subList before you call this method.");
        Map<String, Expression> expressions = buildExpressions(attributes, mapper);
        StandardEvaluationContext context = new StandardEvaluationContext();
        Collection<Map<String, Object>> results = new ArrayList<Map<String, Object>>();
        for (T object : input) {
            Map<String, Object> map = new LinkedHashMap<String, Object>();
            for (String attribute : expressions.keySet()) {
                map.put(attribute, expressions.get(attribute).getValue(context, object));
            }
            results.add(map);
        }

        return new SearchResults<Map<String, Object>>(schemas, results, startIndex, count, total);
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
