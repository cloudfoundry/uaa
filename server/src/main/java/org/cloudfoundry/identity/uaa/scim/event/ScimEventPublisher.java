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
package org.cloudfoundry.identity.uaa.scim.event;

import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

import java.util.List;


public class ScimEventPublisher implements ApplicationEventPublisherAware {
    private ApplicationEventPublisher publisher;
    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public void userCreated(ScimUser user) {
        publish(UserModifiedEvent.userCreated(user.getId(), user.getUserName()));
    }

    public void userVerified(ScimUser user) {
        publish(UserModifiedEvent.userVerified(user.getId(), user.getUserName()));
    }

    public void userModified(ScimUser user) {
        publish(UserModifiedEvent.userModified(user.getId(), user.getUserName()));
    }

    public void userDeleted(ScimUser user) {
        publish(UserModifiedEvent.userDeleted(user.getId(), user.getUserName()));
    }

    public void groupCreated(ScimGroup group) {
        publish(GroupModifiedEvent.groupCreated(group.getId(), group.getDisplayName(), getMembers(group)));
    }

    public void groupModified(ScimGroup group) {
        publish(GroupModifiedEvent.groupModified(group.getId(), group.getDisplayName(), getMembers(group)));
    }

    public void groupDeleted(ScimGroup group) {
        publish(GroupModifiedEvent.groupDeleted(group.getId(), group.getDisplayName(), getMembers(group)));
    }

    public static String[] getMembers(ScimGroup group) {
        List<ScimGroupMember> gm = group.getMembers();
        String[] members = new String[gm!=null?gm.size():0];
        for (int i=0; i<members.length; i++) {
            members[i] = gm.get(i).getMemberId();
        }
        return members;
    }

    public void publish(ApplicationEvent event) {
        if (publisher!=null) {
            publisher.publishEvent(event);
        }
    }


}
