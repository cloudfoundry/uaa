/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.security;


import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

public class ContextSensitiveOAuth2WebSecurityExpressionHandler extends OAuth2WebSecurityExpressionHandler {

    @Override
    protected StandardEvaluationContext createEvaluationContextInternal(
            Authentication authentication,
            FilterInvocation invocation) {
        StandardEvaluationContext ec = super.createEvaluationContextInternal(authentication, invocation);
        ec.setVariable("oauth2", new ContextSensitiveOAuth2SecurityExpressionMethods(authentication));
        return ec;
    }
}
