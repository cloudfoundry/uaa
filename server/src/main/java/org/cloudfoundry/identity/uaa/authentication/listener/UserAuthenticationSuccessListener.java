package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.context.ApplicationListener;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class UserAuthenticationSuccessListener implements ApplicationListener<UserAuthenticationSuccessEvent> {

    private final ScimUserProvisioning scimUserProvisioning;

    public UserAuthenticationSuccessListener(ScimUserProvisioning scimUserProvisioning) {
        this.scimUserProvisioning = scimUserProvisioning;
    }

    @Override
    public void onApplicationEvent(UserAuthenticationSuccessEvent event) {
        UaaUser user = event.getUser();
        if(user.isLegacyVerificationBehavior() && !user.isVerified()) {
            scimUserProvisioning.verifyUser(user.getId(), -1);
        }
        UaaAuthentication authentication = (UaaAuthentication) event.getAuthentication();
        authentication.setLastLoginSuccessTime(user.getLastLogonTime());
        scimUserProvisioning.updateLastLogonTime(user.getId());
    }
}
