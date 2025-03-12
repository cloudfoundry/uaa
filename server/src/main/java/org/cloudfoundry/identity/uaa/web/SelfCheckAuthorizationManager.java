package org.cloudfoundry.identity.uaa.web;

import java.util.function.Supplier;
import javax.servlet.http.HttpServletRequest;

import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public class SelfCheckAuthorizationManager  implements AuthorizationManager<RequestAuthorizationContext> {

    private final IsSelfCheck selfCheck;
    private final int parameterIndex;

	public SelfCheckAuthorizationManager(IsSelfCheck selfCheck, int parameterIndex) {
		this.selfCheck = selfCheck;
		this.parameterIndex = parameterIndex;
	}

	@Override
    public void verify(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
        AuthorizationManager.super.verify(authentication, context);
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
        HttpServletRequest request = context.getRequest();
        // perform authorization looking for the user ID in the URL
        if (this.selfCheck.isUserSelf(request, this.parameterIndex)) {
            return new AuthorizationDecision(true);
        } else {
            return new AuthorizationDecision(false);
        }
    }
}
