package org.cloudfoundry.identity.uaa.audit;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.ge.predix.audit.sdk.AuditCallback;
import com.ge.predix.audit.sdk.AuditClient;
import com.ge.predix.audit.sdk.AuditClientType;
import com.ge.predix.audit.sdk.FailReport;
import com.ge.predix.audit.sdk.config.AuditConfiguration;
import com.ge.predix.audit.sdk.exception.AuditException;
import com.ge.predix.audit.sdk.message.AuditEvent;
import com.ge.predix.audit.sdk.message.AuditEventV2;
import com.ge.predix.audit.sdk.validator.ValidatorReport;
import com.ge.predix.eventhub.EventHubClientException;

@Configuration
@Profile({ "!predixaudit" })
public class LocalPredixAuditConfig {
    private static final Logger log = LoggerFactory.getLogger(PredixAuditConfig.class);

    @Value("${AUDIT_UAA_URL}")
    private String uaaUrl;

    @Value("${AUDIT_CLIENT_ID}")
    private String auditClientId;

    @Value("${AUDIT_CLIENT_SECRET}")
    private String auditClientSecret;

    @Value("${AUDIT_EHUB_ZONE_ID}")
    private String auditEhubZoneId;

    @Value("${AUDIT_EHUB_HOST}")
    private String auditEhubHost;

    @Value("${AUDIT_EHUB_PORT}")
    private String auditEhubPort;

    @Bean
    public AuditClient auditClient() throws AuditException, EventHubClientException {
        log.info("-------------------Creating Audit Client");
        AuditConfiguration sdkConfig = getConfig();
        AuditCallback auditCallback = auditCallback();
        return new AuditClient(sdkConfig, auditCallback);
    }

    private AuditConfiguration getConfig() {
        log.info("-AUDIT_UAA_URL: " + uaaUrl);
        log.info("-AUDIT_CLIENT_ID: " + auditClientId);
        log.info("-AUDIT_CLIENT_SECRET: " + auditClientSecret);
        log.info("-AUDIT_EHUB_ZONE_ID: " + auditEhubZoneId);
        log.info("-AUDIT_EHUB_HOST: " + auditEhubHost);
        log.info("-AUDIT_EHUB_PORT: " + auditEhubPort);
        return AuditConfiguration.builder()
                .bulkMode(true)
                .clientType(AuditClientType.ASYNC)
                .uaaUrl(uaaUrl)
                .uaaClientId(auditClientId)
                .uaaClientSecret(auditClientSecret)
                .ehubZoneId(auditEhubZoneId)
                .ehubHost(auditEhubHost)
                .ehubPort(Integer.parseInt(auditEhubPort))
                .build();
    }

    public AuditCallback auditCallback() {
        return new AuditCallback() {
            @Override
            public void onValidate(AuditEvent auditEvent, List<ValidatorReport> list) {
                log.info("onValidate {}", list);
                // Check the sanitized report:
                list.forEach(validatorReport -> {
                    validatorReport.getOriginalMessage(); // Original messages
                    validatorReport.getSanitizedMessage(); // Sanitized messages
                });
            }

            @Override
            public void onFailure(AuditEvent auditEvent, FailReport failReport, String description) {
                log.info("onFailure {} \n {} \n {}", failReport, auditEvent, description);
            }

            @Override
            public void onFailure(FailReport failReport, String description) {
                log.info("onFailure {} \n {}", failReport, description);
            }

            @Override
            public void onSuccees(AuditEvent auditEvent) {
                log.info("onSuccess {}", auditEvent);
            }

        };
    }
    
}
