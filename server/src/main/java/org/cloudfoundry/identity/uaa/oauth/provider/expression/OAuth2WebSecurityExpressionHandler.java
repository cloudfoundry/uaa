package org.cloudfoundry.identity.uaa.oauth.provider.expression;

import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;

public class OAuth2WebSecurityExpressionHandler extends DefaultWebSecurityExpressionHandler {
	public OAuth2WebSecurityExpressionHandler() {
		setExpressionParser(new OAuth2ExpressionParser(getExpressionParser()));
	}

	@Override
	protected StandardEvaluationContext createEvaluationContextInternal(Authentication authentication,
			FilterInvocation invocation) {
		StandardEvaluationContext ec = super.createEvaluationContextInternal(authentication, invocation);
		ec.setVariable("oauth2", new OAuth2SecurityExpressionMethods(authentication));
		return ec;
	}
}