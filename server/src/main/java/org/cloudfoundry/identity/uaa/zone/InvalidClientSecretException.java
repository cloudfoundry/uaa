package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class InvalidClientSecretException extends InvalidClientDetailsException {

    private final List<String> errorMessages;

    public InvalidClientSecretException(String message) {
        super(message);
        errorMessages = Collections.singletonList(message);
    }

    public InvalidClientSecretException(List<String> errorMessages) {
        super(concatenate(errorMessages));
        this.errorMessages = errorMessages;
    }

    public List<String> getErrorMessages() {
        return errorMessages;
    }

    public String getMessagesAsOneString() {
        return concatenate(errorMessages);
    }

    private static String concatenate(List<String> errorMessages) {
        ArrayList<String> sortedMessages = new ArrayList<>(errorMessages);
        Collections.sort(sortedMessages);
        return StringUtils.collectionToDelimitedString(sortedMessages, " ");
    }
}