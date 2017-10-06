package org.cloudfoundry.identity.uaa.message;

public interface MessageService {

    void sendMessage(String email, MessageType messageType, String subject, String htmlContent);

}
