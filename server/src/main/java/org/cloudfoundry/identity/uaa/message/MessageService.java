package org.cloudfoundry.identity.uaa.message;

public interface MessageService {

    public void sendMessage(String email, MessageType messageType, String subject, String htmlContent);

}
