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
package org.cloudfoundry.identity.app.web;

import java.util.Map;

import org.springframework.context.expression.MapAccessor;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class MapWrapper {

    private final SpelExpressionParser parser;

    private final StandardEvaluationContext context;

    private Object target;

    public MapWrapper(Object target) {
        this.target = target;
        context = new StandardEvaluationContext();
        context.addPropertyAccessor(new MapAccessor());
        parser = new SpelExpressionParser();
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> getMap() {
        return (Map<String, Object>) target;
    }

    public Object get(String expression) throws Exception {
        return get(expression, Object.class);
    }

    public <T> T get(String expression, Class<T> type) {
        return parser.parseExpression(expression).getValue(context, target,
                        type);
    }

    @Override
    public String toString() {
        return target.toString();
    }

}