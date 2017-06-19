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
package org.cloudfoundry.identity.uaa.audit;

import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.util.concurrent.atomic.AtomicLong;

/**
 * An audit service that subscribes to audit events but only saves enough data
 * to answer queries about consecutive
 * failed logins.
 */
public class JdbcFailedLoginCountingAuditService extends JdbcAuditService {

    private int saveDataPeriodMillis = 24 * 3600 * 1000; // 24hr
    private long timeBetweenDeleteMillis = 1000*30;

    private AtomicLong lastDelete = new AtomicLong(0);
    private TimeService timeService = new TimeServiceImpl();

    public JdbcFailedLoginCountingAuditService(JdbcTemplate template) {
        super(template);
    }

    /**
     * @param saveDataPeriodMillis the period in milliseconds to set
     */
    public void setSaveDataPeriodMillis(int saveDataPeriodMillis) {
        this.saveDataPeriodMillis = saveDataPeriodMillis;
    }

    public void setTimeService(TimeService timeService) {
        this.timeService = timeService;
    }

    @Override
    public void log(AuditEvent auditEvent) {
        switch (auditEvent.getType()) {
            case UserAuthenticationSuccess:
            case PasswordChangeSuccess:
            case UserAccountUnlockedEvent:
                getJdbcTemplate().update("delete from sec_audit where principal_id=?", auditEvent.getPrincipalId());
                break;
            case UserAuthenticationFailure:
                periodicDelete();
                super.log(auditEvent);
                break;
            default:
                break;
        }
    }

    protected void periodicDelete() {
        long now = timeService.getCurrentTimeMillis();
        long lastCheck = lastDelete.get();
        if (now - lastCheck > timeBetweenDeleteMillis && lastDelete.compareAndSet(lastCheck, now)) {
            getJdbcTemplate().update("delete from sec_audit where created < ?",
                                     new Timestamp(System.currentTimeMillis()
                                                       - saveDataPeriodMillis));
        }
    }

}
