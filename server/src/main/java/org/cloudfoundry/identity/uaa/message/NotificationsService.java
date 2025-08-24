package org.cloudfoundry.identity.uaa.message;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

public class NotificationsService implements MessageService {
    private final RestTemplate notificationsTemplate;
    private final String notificationsUrl;
    private final Map<MessageType, HashMap<String, Object>> notifications;
    private final boolean sendInDefaultZone;

    private Boolean isNotificationsRegistered = false;

    public Boolean getIsNotificationsRegistered() {
        return isNotificationsRegistered;
    }

    public NotificationsService(RestTemplate notificationsTemplate,
            String notificationsUrl,
            Map<MessageType, HashMap<String, Object>> notifications,
            boolean sendInDefaultZone) {
        this.notificationsTemplate = notificationsTemplate;
        this.notificationsUrl = notificationsUrl;
        this.notifications = notifications;
        this.sendInDefaultZone = sendInDefaultZone;
    }

    public boolean isSendInDefaultZone() {
        return sendInDefaultZone;
    }

    @Override
    public void sendMessage(String email, MessageType messageType, String subject, String htmlContent) {
        IdentityZone current = IdentityZoneHolder.get();
        try {
            if (isSendInDefaultZone()) {
                IdentityZoneHolder.set(IdentityZone.getUaa());
            }
            internalSendMessage(email, messageType, subject, htmlContent);
        } finally {
            IdentityZoneHolder.set(current);
        }
    }

    protected void internalSendMessage(String email, MessageType messageType, String subject, String htmlContent) {
        if (!getIsNotificationsRegistered()) {
            registerNotifications();
        }

        Map<String, String> request = new HashMap<>();
        String kindId = (String) notifications.get(messageType).get("id");
        request.put("kind_id", kindId);
        request.put("to", email);
        request.put("subject", subject);
        request.put("html", htmlContent);

        HttpEntity<Map<String, String>> requestEntity = new HttpEntity<>(request);
        notificationsTemplate.exchange(notificationsUrl + "/emails", HttpMethod.POST, requestEntity, Void.class);
    }

    private void registerNotifications() {
        HashMap<String, Object> request = new HashMap<>();
        request.put("source_description", "CF_Identity");
        request.put("kinds", notifications.values());

        notificationsTemplate.put(notificationsUrl + "/registration", request);
        isNotificationsRegistered = true;
    }
}
