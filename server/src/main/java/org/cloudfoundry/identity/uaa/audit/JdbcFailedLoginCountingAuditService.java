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

import java.sql.Timestamp;

import javax.sql.DataSource;

/**
 * An audit service that subscribes to audit events but only saves enough data
 * to answer queries about consecutive
 * failed logins.
 * 
 * @author Dave Syer
 */
public class JdbcFailedLoginCountingAuditService extends JdbcAuditService {

    private int saveDataPeriodMillis = 2 * 3600 * 1000; // 2hr

    public JdbcFailedLoginCountingAuditService(DataSource dataSource) {
        super(dataSource);
    }

    /**
     * @param saveDataPeriodMillis the period in milliseconds to set
     */
    public void setSaveDataPeriodMillis(int saveDataPeriodMillis) {
        this.saveDataPeriodMillis = saveDataPeriodMillis;
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
                getJdbcTemplate().update("delete from sec_audit where created < ?",
                                new Timestamp(System.currentTimeMillis()
                                                - saveDataPeriodMillis));
                super.log(auditEvent);
                break;
            default:
                break;
        }
    }

}
