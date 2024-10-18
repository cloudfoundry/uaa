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
package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.springframework.security.core.Authentication;

/**
 * @author Luke Taylor
 */
public abstract class AbstractUaaAuthenticationEvent extends AbstractUaaEvent {

    AbstractUaaAuthenticationEvent(Authentication authentication, String zoneId) {
        super(authentication, zoneId);
    }

    protected String getOrigin(UaaAuthenticationDetails details) {
        return details == null ? "unknown" : details.toString();
    }

    UaaAuthenticationDetails getAuthenticationDetails() {
        return (UaaAuthenticationDetails) getAuthentication().getDetails();
    }

}
