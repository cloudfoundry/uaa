package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2ExpressionUtils;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;

/**
 * Controller that sends user info to clients wishing to authenticate.
 */
@Controller
public class UserInfoEndpoint implements InitializingBean {

    private final UaaUserDatabase userDatabase;

    public UserInfoEndpoint(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.state(userDatabase != null, "A user database must be provided");
    }

    @RequestMapping(value = "/userinfo")
    @ResponseBody
    public UserInfoResponse loginInfo(Principal principal) {
        OAuth2Authentication authentication = (OAuth2Authentication) principal;
        UaaPrincipal uaaPrincipal = extractUaaPrincipal(authentication);
        boolean addCustomAttributes = OAuth2ExpressionUtils.hasAnyScope(authentication, new String[]{USER_ATTRIBUTES});
        boolean addRoles = OAuth2ExpressionUtils.hasAnyScope(authentication, new String[]{ROLES});
        return getResponse(uaaPrincipal, addCustomAttributes, addRoles);
    }

    protected UaaPrincipal extractUaaPrincipal(OAuth2Authentication authentication) {
        Object object = authentication.getUserAuthentication().getPrincipal();
        if (object instanceof UaaPrincipal principal) {
            return principal;
        }
        throw new IllegalStateException("User authentication could not be converted to UaaPrincipal");
    }

    protected UserInfoResponse getResponse(UaaPrincipal principal, boolean addCustomAttributes, boolean addRoles) {
        UaaUserPrototype user = userDatabase.retrieveUserPrototypeById(principal.getId());
        UserInfoResponse response = new UserInfoResponse();
        response.setUserId(user.getId());
        response.setUserName(user.getUsername());
        response.setGivenName(user.getGivenName());
        response.setFamilyName(user.getFamilyName());
        response.setEmail(user.getEmail());
        response.setEmailVerified(user.isVerified());
        response.setPhoneNumber(user.getPhoneNumber());
        response.setPreviousLogonSuccess(user.getPreviousLogonTime());

        UserInfo info = userDatabase.getUserInfo(user.getId());
        if (addCustomAttributes && info != null) {
            response.setUserAttributes(info.getUserAttributes());
        }
        if (addRoles && info != null) {
            response.setRoles(info.getRoles());
        }
        return response;
    }
}

