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

package org.cloudfoundry.identity.api.web;

import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.expression.MapAccessor;
import org.springframework.core.io.Resource;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Controller;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.PropertyPlaceholderHelper;
import org.springframework.util.PropertyPlaceholderHelper.PlaceholderResolver;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.View;

/**
 * @author Dave Syer
 * 
 */
@Controller
public class ApiController {

    private String infoResource;
    private String loginUrl = "http://localhost:8080/uaa";
    private String uaaUrl = "http://localhost:8080/uaa";

    /**
     * @param loginUrl the loginUrl to set
     */
    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    /**
     * @param uaaUrl the uaaUrl to set
     */
    public void setUaaUrl(String uaaUrl) {
        this.uaaUrl = uaaUrl;
    }

    /**
     * @param info the info to set
     */
    public void setInfo(Resource info) {
        try {
            this.infoResource = FileCopyUtils.copyToString(new InputStreamReader(info.getInputStream()));
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not load template", e);
        }
    }

    @RequestMapping("/info")
    public View info(Map<String, Object> model, Principal principal) throws Exception {
        model.put("loginUrl", loginUrl);
        model.put("uaaUrl", uaaUrl);
        if (principal != null) {
            model.put("user", principal.getName());
        } else {
            model.put("user", null);
        }
        return new SpelView(infoResource);
    }

    private static class SpelView implements View {

        private final String template;

        private final SpelExpressionParser parser = new SpelExpressionParser();

        private final StandardEvaluationContext context = new StandardEvaluationContext();

        private PropertyPlaceholderHelper helper;

        private PlaceholderResolver resolver;

        public SpelView(String template) {
            this.template = template;
            this.context.addPropertyAccessor(new MapAccessor());
            this.helper = new PropertyPlaceholderHelper("${", "}");
            this.resolver = new PlaceholderResolver() {
                @Override
                public String resolvePlaceholder(String name) {
                    Expression expression = parser.parseExpression(name);
                    Object value = expression.getValue(context);
                    return value == null ? null : value.toString();
                }
            };
        }

        @Override
        public String getContentType() {
            return "application/json";
        }

        @Override
        public void render(Map<String, ?> model, HttpServletRequest request, HttpServletResponse response)
                        throws Exception {
            if (response.getContentType() == null) {
                response.setContentType(getContentType());
            }
            Map<String, Object> map = new HashMap<String, Object>(model);
            map.put("path", request.getContextPath());
            context.setRootObject(map);
            String result = helper.replacePlaceholders(template, resolver);
            response.getWriter().append(result);
        }

    }
}
