/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.zone.event;


import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;

public class ServiceProviderModifiedEvent extends AbstractUaaEvent {

    private static final long serialVersionUID = -204120790766086570L;

    private AuditEventType eventType;

    protected static final String dataFormat = "id=%s; name=%s; entityID=%s";

    public ServiceProviderModifiedEvent(SamlServiceProvider serviceProvider, Authentication authentication, AuditEventType type, String zoneId) {
        super(serviceProvider, authentication, zoneId);
        eventType = type;
    }

    @Override
    public AuditEvent getAuditEvent() {
        SamlServiceProvider provider = (SamlServiceProvider)source;
        return createAuditRecord(getSource().toString(),
                                 eventType,
                                 getOrigin(getAuthentication()),
                                 String.format(dataFormat,
                                               provider.getId(),
                                               provider.getName(),
                                               provider.getEntityId()));
    }

    public static ServiceProviderModifiedEvent serviceProviderCreated(SamlServiceProvider serviceProvider) {
        return new ServiceProviderModifiedEvent(serviceProvider, getContextAuthentication(), AuditEventType.ServiceProviderCreatedEvent, IdentityZoneHolder.getCurrentZoneId());
    }

    public static ServiceProviderModifiedEvent serviceProviderModified(SamlServiceProvider serviceProvider) {
        return new ServiceProviderModifiedEvent(serviceProvider, getContextAuthentication(), AuditEventType.ServiceProviderModifiedEvent, IdentityZoneHolder.getCurrentZoneId());
    }

}
