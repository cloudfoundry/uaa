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
package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.springframework.context.ApplicationListener;
import org.springframework.util.Assert;

/**
 * Spring {@code ApplicationListener} which picks up the listens for
 * {@code AbstractUaaEvent}s and passes the relevant
 * information to the {@code UaaAuditService}.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
public class AuditListener implements ApplicationListener<AbstractUaaEvent> {
    private final UaaAuditService uaaAuditService;

    public AuditListener() {
        uaaAuditService = new LoggingAuditService();
    }

    public AuditListener(UaaAuditService auditor) {
        Assert.notNull(auditor);
        this.uaaAuditService = auditor;
    }

    @Override
    public void onApplicationEvent(AbstractUaaEvent event) {
        event.process(uaaAuditService);
        
    }

}
