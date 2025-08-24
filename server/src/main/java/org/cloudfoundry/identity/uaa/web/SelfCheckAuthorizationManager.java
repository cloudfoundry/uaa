package org.cloudfoundry.identity.uaa.web;

import java.util.function.Supplier;
import jakarta.servlet.http.HttpServletRequest;

import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public class SelfCheckAuthorizationManager  implements AuthorizationManager<RequestAuthorizationContext> {
    private enum CheckType {USER, TOKEN_REVOCATION_USER, TOKEN_REVOCATION_CLIENT, TOKEN_REVOCATION_SELF};
    private final IsSelfCheck selfCheck;
    private final int parameterIndex;
    private final CheckType type;


    public static SelfCheckAuthorizationManager isUserSelf(IsSelfCheck selfCheck, int parameterIndex) {
        return new SelfCheckAuthorizationManager(CheckType.USER, selfCheck, parameterIndex);
    }

    public static SelfCheckAuthorizationManager isUserTokenRevocationForSelf(IsSelfCheck selfCheck, int parameterIndex) {
        return new SelfCheckAuthorizationManager(CheckType.TOKEN_REVOCATION_USER, selfCheck, parameterIndex);
    }

    public static SelfCheckAuthorizationManager isClientTokenRevocationForSelf(IsSelfCheck selfCheck, int parameterIndex) {
        return new SelfCheckAuthorizationManager(CheckType.TOKEN_REVOCATION_CLIENT, selfCheck, parameterIndex);
    }

    public static SelfCheckAuthorizationManager isTokenRevocationForSelf(IsSelfCheck selfCheck, int parameterIndex) {
        return new SelfCheckAuthorizationManager(CheckType.TOKEN_REVOCATION_SELF, selfCheck, parameterIndex);
    }

    private SelfCheckAuthorizationManager(CheckType type, IsSelfCheck selfCheck, int parameterIndex) {
		this.type = type;
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
        switch (type) {
            case USER -> {
                if (this.selfCheck.isUserSelf(request, this.parameterIndex)) {
                    return new AuthorizationDecision(true);
                }
            }
            case TOKEN_REVOCATION_USER -> {
                if (this.selfCheck.isUserTokenRevocationForSelf(request, this.parameterIndex)) {
                    return new AuthorizationDecision(true);
                }
            }
            case TOKEN_REVOCATION_CLIENT -> {
                if (this.selfCheck.isClientTokenRevocationForSelf(request, this.parameterIndex)) {
                    return new AuthorizationDecision(true);
                }
            }
            case TOKEN_REVOCATION_SELF -> {
                if (this.selfCheck.isTokenRevocationForSelf(request, this.parameterIndex)) {
                    return new AuthorizationDecision(true);
                }
            }
        }
        return new AuthorizationDecision(false);
    }
}
