package org.cloudfoundry.identity.uaa.provider.saml;

import com.ge.iam.sns.service.MessageBuilder;
import com.ge.iam.sns.service.SnsService;
import com.google.gson.JsonObject;
import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.events.UserAttributeChangedEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
@EnableAsync
public class UserAttributeChangesSnsHandler {

    private final static Logger logger = LoggerFactory.getLogger(UserAttributeChangesSnsHandler.class);

    @Value("${sns.topic.arn:arn}")
    private String snsTopicArn;

    @Value("${sns.enabled:false}")
    private boolean snsEnabled;

    private final SnsService snsService;

    public UserAttributeChangesSnsHandler(SnsService snsService) {
        this.snsService = snsService;
        logger.debug("UserAttributeChangesSnsHandler initialized with SNS service");
    }


    @EventListener
    @Async
    public void handleUserAttributeChanged(UserAttributeChangedEvent event) {
        UaaUser existingUser = event.getExistingUser();
        UaaUser updatedUser = event.getUpdatedUser();

        try {
            // Check if SNS is enabled
            if (!snsEnabled) {
                logger.debug("SNS publishing is disabled, skipping for user: {}",
                        updatedUser != null ? updatedUser.getUsername() : "unknown");
                return;
            }

            // Validate inputs to prevent unnecessary processing
            if (existingUser == null || updatedUser == null) {
                logger.warn("Skipping SNS publish - null user provided: existing={}, updated={}",
                        existingUser != null, updatedUser != null);
                return;
            }

            // Early validation of SNS configuration
            if (StringUtils.isBlank(snsTopicArn) || "arn".equals(snsTopicArn)) {
                logger.debug("SNS topic ARN not configured, skipping publish");
                return;
            }

            Map<String, Object> changedFields = getChangedFields(existingUser, updatedUser);
        
            logger.debug("Processing user attribute change event: {} field(s) changed", changedFields.keySet());

            if (changedFields.isEmpty()) {
                logger.debug("No changes detected, skipping publish");
                return;
            }

            MessageBuilder userEventMessageBuilder = () -> {
                try {
                    // Build the complete message structure
                    Map<String, Object> messageMap = createUserEventMessage(updatedUser, changedFields);

                    JsonObject jsonMessage = new JsonObject();
                    
                    // Add all fields from the message map to JsonObject
                    messageMap.forEach((key, value) -> {
                        if (value instanceof String) {
                            jsonMessage.addProperty(key, (String) value);
                        } else if (value instanceof Number) {
                            jsonMessage.addProperty(key, (Number) value);
                        } else if (value instanceof Boolean) {
                            jsonMessage.addProperty(key, (Boolean) value);
                        } else if (value instanceof Map) {
                            // Handle nested objects like changedFields
                            JsonObject nestedObject = new JsonObject();
                            ((Map<?, ?>) value).forEach((nestedKey, nestedValue) -> {
                                if (nestedValue instanceof String) {
                                    nestedObject.addProperty(nestedKey.toString(), (String) nestedValue);
                                } else if (nestedValue instanceof Number) {
                                    nestedObject.addProperty(nestedKey.toString(), (Number) nestedValue);
                                } else if (nestedValue instanceof Boolean) {
                                    nestedObject.addProperty(nestedKey.toString(), (Boolean) nestedValue);
                                } else if (nestedValue != null) {
                                    nestedObject.addProperty(nestedKey.toString(), nestedValue.toString());
                                }
                            });
                            jsonMessage.add(key, nestedObject);
                        } else if (value != null) {
                            jsonMessage.addProperty(key, value.toString());
                        }
                    });
                    
                    logger.debug("Message built asynchronously in thread: {}", Thread.currentThread().getName());
                    
                    return jsonMessage;
                    
                } catch (Exception e) {
                    logger.error("Error building message for user event", e);
                    throw new RuntimeException("Failed to build user event message", e);
                }
            };

            snsService.publishAsync(snsTopicArn, "UAA User Event", userEventMessageBuilder)
                .whenComplete((publishResponse, throwable) -> {
                    if (throwable != null) {
                        logger.error("Failed to publish user event to SNS. " +
                                "This failure will not affect application functionality.", throwable);
                    } else {
                        logger.info("User event published to SNS successfully");
                    }
                });

            logger.debug("Async SNS publish initiated");

        } catch (Exception e) {
            logger.error("Failed to initiate SNS publish. " +
                    "This failure will not affect application functionality.", e);
        }
    }

    /**
     * Check if SNS integration is properly configured and enabled
     */
    public boolean isConfiguredAndEnabled() {
        return snsEnabled && !StringUtils.isBlank(snsTopicArn) && !"arn".equals(snsTopicArn);
    }

    private Map<String, Object> getChangedFields(UaaUser existingUser, UaaUser user) {
        Map<String, Object> changedFields = new HashMap<>();

        boolean isFirstTimeLogin = existingUser.getLastLogonTime() == null;

        if (isFirstTimeLogin) {
            if (user.getEmail() != null) {
                changedFields.put("email", user.getEmail());
            }

            if (user.getGivenName() != null) {
                changedFields.put("givenName", user.getGivenName());
            }

            if (user.getFamilyName() != null) {
                changedFields.put("familyName", user.getFamilyName());
            }

            if (user.getPhoneNumber() != null) {
                changedFields.put("phoneNumber", user.getPhoneNumber());
            }

            changedFields.put("lastLogonTime", user.getLastLogonTime());

            return changedFields;
        }

        if (!StringUtils.equals(existingUser.getEmail(), user.getEmail())) {
            changedFields.put("email", user.getEmail());
        }

        boolean givenNameChanged = !StringUtils.equals(existingUser.getGivenName(), user.getGivenName());
        boolean familyNameChanged = !StringUtils.equals(existingUser.getFamilyName(), user.getFamilyName());

        boolean isNameSwap = StringUtils.equals(existingUser.getGivenName(), user.getFamilyName()) &&
                StringUtils.equals(existingUser.getFamilyName(), user.getGivenName());

        if (givenNameChanged && !isNameSwap) {
            changedFields.put("givenName", user.getGivenName());
        }

        if (familyNameChanged && !isNameSwap) {
            changedFields.put("familyName", user.getFamilyName());
        }

        if (!StringUtils.equals(existingUser.getPhoneNumber(), user.getPhoneNumber())) {
            changedFields.put("phoneNumber", user.getPhoneNumber());
        }

        if (!StringUtils.equals(existingUser.getUsername(), user.getUsername())) {
            changedFields.put("username", user.getUsername());
        }

        if (!java.util.Objects.equals(existingUser.getLastLogonTime(), user.getLastLogonTime())) {
            changedFields.put("lastLogonTime", user.getLastLogonTime());
        }

        return changedFields;
    }

    private Map<String, Object> createUserEventMessage(UaaUser user, Map<String, Object> changedFields) {
        Map<String, Object> message = new HashMap<>();

        String eventType = determineEventType(changedFields);
        message.put("eventType", eventType);
        message.put("source", "uaa-saml-provider");
        message.put("version", "1.0");
        message.put("username", user.getUsername());

        message.put("instanceZoneId", user.getZoneId());

        message.put("changedFields", changedFields);

        return message;
    }

    private String determineEventType(Map<String, Object> changedFields) {
        if (changedFields.size() == 1 && changedFields.containsKey("lastLogonTime")) {
            return "LOGIN_TIME_UPDATED";
        }
        else {
            return "USER_DATA_UPDATED";
        }
    }
}
