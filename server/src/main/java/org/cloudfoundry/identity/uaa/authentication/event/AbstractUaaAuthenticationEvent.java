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

import java.util.StringJoiner;

import static org.springframework.util.StringUtils.hasText;

/**
 * @author Luke Taylor
 */
public abstract class AbstractUaaAuthenticationEvent extends AbstractUaaEvent {

    AbstractUaaAuthenticationEvent(Authentication authentication, String zoneId) {
        super(authentication, zoneId);
    }

    protected String getOrigin(UaaAuthenticationDetails details) {
        if (details == null) {
            return "unknown";
        }

        StringJoiner joiner = new StringJoiner(", ");

        if (hasText(details.getOrigin())) {
            joiner.add("remoteAddress=" + details.getOrigin());
        }

        if (hasText(details.getClientId())) {
            joiner.add("clientId=" + details.getClientId());
        }

        return joiner.length() == 0 ? "unknown" : joiner.toString();
    }

    UaaAuthenticationDetails getAuthenticationDetails() {
        return (UaaAuthenticationDetails) getAuthentication().getDetails();
    }

}
