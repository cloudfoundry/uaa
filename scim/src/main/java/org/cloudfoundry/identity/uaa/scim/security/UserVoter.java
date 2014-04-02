/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.security;

import java.util.Collection;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.StringUtils;

public class UserVoter implements AccessDecisionVoter<Object> {

    private String configAttribute = "user=self";

    public void setConfigAttribute(String configAttribute) {
        this.configAttribute = configAttribute;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return (StringUtils.hasText(attribute.getAttribute()) && attribute.getAttribute().equalsIgnoreCase(
                        configAttribute));
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        if (authentication instanceof OAuth2Authentication && ((OAuth2Authentication) authentication).isClientOnly()) {
            return ACCESS_ABSTAIN;
        }
        for (ConfigAttribute attribute : attributes) {
            if (supports(attribute)) {
                if (authentication.getPrincipal() instanceof UaaPrincipal) {
                    String userIdInContext = ((UaaPrincipal) authentication.getPrincipal()).getId();
                    String userIdInRequest = getIdInPathParam(((FilterInvocation) object).getRequestUrl());
                    return userIdInContext.equals(userIdInRequest) ? ACCESS_GRANTED : ACCESS_DENIED;
                }
            }
        }
        return ACCESS_ABSTAIN;
    }

    private String getIdInPathParam(String url) {
        int startIndex = url.lastIndexOf("/") + 1;
        int endIndex = url.indexOf("?") > 0 ? url.indexOf("?") : url.length();
        return url.substring(startIndex, endIndex);
    }
}
