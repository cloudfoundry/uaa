package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuditListenerConfig {

    @Bean
    public AuditListener loggingAuditListener(
            @Qualifier("loggingAuditService") UaaAuditService loggingAuditService
    ) {
        return new AuditListener(loggingAuditService);
    }

    @Bean
    public AuditListener jdbcAuditListener(
            @Qualifier("jdbcAuditService") UaaAuditService jdbcAuditService
    ) {
        return new AuditListener(jdbcAuditService);
    }

}
