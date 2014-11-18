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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.event.UnverifiedUserAuthenticationEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.context.ApplicationListener;

/**
 * Listens for when unverified users try to log in, and resends a verification email.
 * @author Will Tran
 */
public class UnverifiedUserListener implements ApplicationListener<UnverifiedUserAuthenticationEvent> {

    private AccountCreationService accountCreationService;

    public void setAccountCreationService(AccountCreationService accountCreationService) {
        this.accountCreationService = accountCreationService;
    }

    @Override
    public void onApplicationEvent(UnverifiedUserAuthenticationEvent event) {
        if (event.getAuthentication().getDetails() instanceof UaaAuthenticationDetails) {
            UaaUser user = event.getUser();
            UaaAuthenticationDetails details = (UaaAuthenticationDetails) event.getAuthentication().getDetails();
            accountCreationService.resendVerificationCode(user.getUsername(), details.getClientId());
        }        
    }

}
