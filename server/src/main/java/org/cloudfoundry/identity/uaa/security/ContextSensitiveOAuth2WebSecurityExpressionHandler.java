package org.cloudfoundry.identity.uaa.security;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.web.FilterInvocation;

public class ContextSensitiveOAuth2WebSecurityExpressionHandler
    extends OAuth2WebSecurityExpressionHandler {

  private IdentityZone identityZone;

  @Override
  protected StandardEvaluationContext createEvaluationContextInternal(
      Authentication authentication, FilterInvocation invocation) {
    StandardEvaluationContext ec =
        super.createEvaluationContextInternal(authentication, invocation);
    ec.setVariable(
        "oauth2",
        new ContextSensitiveOAuth2SecurityExpressionMethods(authentication, identityZone));
    return ec;
  }

  public void setIdentityZone(IdentityZone identityZone) {
    this.identityZone = identityZone;
  }
}
