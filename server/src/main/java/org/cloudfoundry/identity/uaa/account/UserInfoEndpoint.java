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
package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2ExpressionUtils;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;


/**
 * Controller that sends user info to clients wishing to authenticate.
 *
 * @author Dave Syer
 */
@Controller
public class UserInfoEndpoint implements InitializingBean {

    private UaaUserDatabase userDatabase;

    public void setUserDatabase(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.state(userDatabase != null, "A user database must be provided");
    }

    @RequestMapping(value = "/userinfo")
    @ResponseBody
    public UserInfoResponse loginInfo(Principal principal) {
        OAuth2Authentication authentication = (OAuth2Authentication) principal;
        UaaPrincipal uaaPrincipal = extractUaaPrincipal(authentication);
        boolean addCustomAttributes = OAuth2ExpressionUtils.hasAnyScope(authentication, new String[] {USER_ATTRIBUTES});
        return getResponse(uaaPrincipal, addCustomAttributes);
    }

    protected UaaPrincipal extractUaaPrincipal(OAuth2Authentication authentication) {
        Object object = authentication.getUserAuthentication().getPrincipal();
        if (object instanceof UaaPrincipal) {
            return (UaaPrincipal) object;
        }
        throw new IllegalStateException("User authentication could not be converted to UaaPrincipal");
    }

    protected UserInfoResponse getResponse(UaaPrincipal principal, boolean addCustomAttributes) {
        UaaUser user = userDatabase.retrieveUserById(principal.getId());
        UserInfoResponse response = new UserInfoResponse();
        response.setUserId(user.getId());
        response.setUsername(user.getUsername());
        response.setGivenName(user.getGivenName());
        response.setFamilyName(user.getFamilyName());
        response.setEmail(user.getEmail());
        response.setPhoneNumber(user.getPhoneNumber());
        response.setSub(user.getId());
        response.setLastLogonSuccess(user.getLastLogonTime());

        if (addCustomAttributes) {
            UserInfo info = userDatabase.getUserInfo(user.getId());
            if (info!=null && info.size()>0) {
                response.setAttributeValue(USER_ATTRIBUTES, info);
            }
        }
        return response;
    }
}

