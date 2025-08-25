/*
 *  Cloud Foundry
 *  Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *  <p/>
 *  This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  You may not use this product except in compliance with the License.
 *  <p/>
 *  This product includes a number of subcomponents with
 *  separate copyright notices and license terms. Your use of these
 *  subcomponents is subject to the terms and conditions of the
 *  subcomponent's license, as noted in the LICENSE file
 */

package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.events.UserAttributeChangedEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * Helper class to handle publishing of user attribute change events.
 * This class is separate to make merging easier when getting latest from UAA.
 */
@Component
public class UserAttributeChangeEventPublisher {

    private final static Logger logger = LoggerFactory.getLogger(UserAttributeChangeEventPublisher.class);

    private final ApplicationEventPublisher publisher;

    @Autowired
    public UserAttributeChangeEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @Async
    public void publishUserAttributeChangeEventAsync(Object source, UaaUser userBeforeLastLogonUpdate,
                                                     UaaUser userAfterLastLogonUpdate) {
        try {
            // Use the parameters directly - don't rely on getPreviousUser()
            // The caller already provides both the before and after users correctly
            UaaUser userBeforeChanges = userBeforeLastLogonUpdate;

            UserAttributeChangedEvent event = new UserAttributeChangedEvent(source, userBeforeChanges,
                    userAfterLastLogonUpdate);
            
            if (publisher != null) {
                publisher.publishEvent(event);
            }
        } catch (Exception e) {
            logger.error("Failed to publish user attribute change event asynchronously", e);
        }
    }
}
