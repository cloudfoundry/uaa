package org.cloudfoundry.identity.uaa.audit;

import java.util.List;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;

import com.ge.predix.audit.sdk.AuditClient;
import com.ge.predix.audit.sdk.message.AuditEnums;
import com.ge.predix.audit.sdk.message.AuditEventV2;
import com.ge.predix.audit.sdk.message.AuditEventV2.AuditEventV2Builder;

public class PredixAuditService implements UaaAuditService {

    private static final String LOG_CORRELATION_ID = "Correlation-Id";
    private final Log logger = LogFactory.getLog("Predix.UAA.Audit");

    @Autowired(required = false)
    private AuditClient predixAuditClient;

    @Override
    public List<AuditEvent> find(String principal, long after) {
        throw new UnsupportedOperationException("This implementation does not store data");
    }

    @Override
    public void log(AuditEvent auditEvent) {
        //map and send to audit service
        String correlationId = getCorrelationId();
        String zoneId = auditEvent.getIdentityZoneId();
        try{
            UUID.fromString(correlationId);
        } catch (Exception e){
            logger.debug("non-request based event, setting correlation Id to all zeros");
            correlationId = null;
        }
        try{
            UUID.fromString(zoneId);
        } catch (Exception e){
            logger.debug("base zone event, setting zone Id to base zone placeholder");
            zoneId = null;
        }
        
        AuditEventV2 predixEvent = constructPredixAuditEvent(auditEvent, correlationId, zoneId);
                
        try {
            logger.debug("Auditing uaa events for Predix. "
                    + predixEvent.getPayload());
            if(this.predixAuditClient != null && predixEvent != null) {
                this.predixAuditClient.audit(predixEvent);
            } else {
                logger.debug("Mock publish to audit service: " + predixEvent.toString());
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
        }

    }

    public String getCorrelationId() {
        return MDC.get(LOG_CORRELATION_ID);
    }

    private AuditEventV2 constructPredixAuditEvent(AuditEvent auditEvent, String correlationId,
            String zoneId) {
        AuditEnums.EventType type;
        AuditEnums.CategoryType category;
        AuditEnums.Classifier status = AuditEnums.Classifier.SUCCESS;
        
        switch(auditEvent.getType()) {
            case UserAuthenticationSuccess:
                category = AuditEnums.CategoryType.AUTHENTICATIONS;
                type = AuditEnums.EventType.LOGIN_SUCCESS;
                break;
            case UserAuthenticationFailure:
                category = AuditEnums.CategoryType.AUTHENTICATIONS;
                type = AuditEnums.EventType.LOGIN_FAILURE;
                status = AuditEnums.Classifier.FAILURE;
                break;
            case UserNotFound:
                category = AuditEnums.CategoryType.AUTHENTICATIONS;
                type = AuditEnums.EventType.AUTHENTICATION_ERROR;
                status = AuditEnums.Classifier.FAILURE;
                break;
            case PasswordChangeSuccess:
                category = AuditEnums.CategoryType.ADMINISTRATIONS;
                type = AuditEnums.EventType.CHANGE_PASSWD_SUCCESS;
                break;
            case PrincipalAuthenticationSuccess:
                category = AuditEnums.CategoryType.AUTHENTICATIONS;
                type = AuditEnums.EventType.LOGIN_SUCCESS;
                break;
            case PrincipalAuthenticationFailure:
                category = AuditEnums.CategoryType.AUTHENTICATIONS;
                type = AuditEnums.EventType.LOGIN_FAILURE;
                status = AuditEnums.Classifier.FAILURE;
                break;
            case PrincipalNotFound:
                category = AuditEnums.CategoryType.AUTHENTICATIONS;
                type = AuditEnums.EventType.AUTHENTICATION_ERROR;
                status = AuditEnums.Classifier.FAILURE;
                break;
            case PasswordChangeFailure:
                category = AuditEnums.CategoryType.ADMINISTRATIONS;
                type = AuditEnums.EventType.CHANGE_PASSWD_FAILURE;
                status = AuditEnums.Classifier.FAILURE;
                break;
            case SecretChangeSuccess:
                category = AuditEnums.CategoryType.ADMINISTRATIONS;
                type = AuditEnums.EventType.CHANGE_PASSWD_SUCCESS;
                break;
            case SecretChangeFailure:
                category = AuditEnums.CategoryType.ADMINISTRATIONS;
                type = AuditEnums.EventType.CHANGE_PASSWD_FAILURE;
                status = AuditEnums.Classifier.FAILURE;
                break;
            case ClientCreateSuccess:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case ClientUpdateSuccess:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case ClientDeleteSuccess:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case ClientApprovalsDeleted:
                category = AuditEnums.CategoryType.API_CALLS;
                type = AuditEnums.EventType.SUCCESS_API_REQUEST;
                break;
            case ClientAuthenticationSuccess:
                category = AuditEnums.CategoryType.AUTHENTICATIONS;
                type = AuditEnums.EventType.LOGIN_SUCCESS;
                break;
            case ClientAuthenticationFailure:
                category = AuditEnums.CategoryType.AUTHENTICATIONS;
                type = AuditEnums.EventType.LOGIN_FAILURE;
                status = AuditEnums.Classifier.FAILURE;
                break;
            case ApprovalModifiedEvent:
                category = AuditEnums.CategoryType.API_CALLS;
                type = AuditEnums.EventType.SUCCESS_API_REQUEST;
                break;
            case TokenIssuedEvent:
                category = AuditEnums.CategoryType.AUTHENTICATIONS;
                type = AuditEnums.EventType.SUCCESS_API_REQUEST;
                break;
            case UserCreatedEvent:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case UserModifiedEvent:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case UserDeletedEvent:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case UserVerifiedEvent:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case PasswordResetRequest:
                category = AuditEnums.CategoryType.API_CALLS;
                type = AuditEnums.EventType.SUCCESS_API_REQUEST;
                break;
            case GroupCreatedEvent:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case GroupModifiedEvent:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case GroupDeletedEvent:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case EmailChangedEvent:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case UnverifiedUserAuthentication:
                category = AuditEnums.CategoryType.AUTHENTICATIONS;
                type = AuditEnums.EventType.LOGIN_SUCCESS;
                break;
            case IdentityProviderCreatedEvent:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case IdentityProviderModifiedEvent:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case IdentityZoneCreatedEvent:
                category = AuditEnums.CategoryType.ADMINISTRATIONS;
                type = AuditEnums.EventType.CHANGE_CONFIGURATIONS_SUCCESS;
                break;
            case IdentityZoneModifiedEvent:
                category = AuditEnums.CategoryType.ADMINISTRATIONS;
                type = AuditEnums.EventType.CHANGE_CONFIGURATIONS_SUCCESS;
                break;
            case EntityDeletedEvent:
                if(auditEvent.getData().contains("IdentityProvider")) {
                    category = AuditEnums.CategoryType.AUTHORIZATION;
                    type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                } else {
                    category = AuditEnums.CategoryType.ADMINISTRATIONS;
                    type = AuditEnums.EventType.CHANGE_CONFIGURATIONS_SUCCESS;
                }
                break;
            case ServiceProviderCreatedEvent:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case ServiceProviderModifiedEvent:
                category = AuditEnums.CategoryType.AUTHORIZATION;
                type = AuditEnums.EventType.ACCOUNT_PRIVILEGE_SUCCESS_MODIFICATION;
                break;
            case UserAccountUnlockedEvent:
                category = AuditEnums.CategoryType.API_CALLS;
                type = AuditEnums.EventType.SUCCESS_API_REQUEST;
                break;
            default:
                return null;
        }

        //Add zone id to the payload if it is not a uuid
        String basePayload = auditEvent.getType().toString() + ": " + auditEvent.getData();
        String payload = (zoneId == null ? "Z: " + auditEvent.getIdentityZoneId() + " " + basePayload : basePayload);

        AuditEventV2Builder predixEventBuilder = AuditEventV2.builder()
                .payload(payload)
                .classifier(status)
                .publisherType(AuditEnums.PublisherType.APP_SERVICE)
                .categoryType(category)
                .eventType(type);
        if(zoneId != null) {
            predixEventBuilder.tenantUuid(zoneId);
        }
        if(correlationId != null) {
            predixEventBuilder.correlationId(correlationId);
        }
        AuditEventV2 predixEvent = predixEventBuilder.build();
        return predixEvent;
    }
}
