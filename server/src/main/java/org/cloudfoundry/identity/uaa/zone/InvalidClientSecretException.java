package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class InvalidClientSecretException extends InvalidClientDetailsException {

    private final List<String> errorMessages;

    public InvalidClientSecretException(String message) {
        super(message);
        errorMessages = Arrays.asList(message);
    }

    public InvalidClientSecretException(List<String> errorMessages) {
        super(StringUtils.collectionToDelimitedString(errorMessages, ","));
        this.errorMessages = errorMessages;
    }

    public List<String> getErrorMessages() {
        return errorMessages;
    }

    public String getMessagesAsOneString() {
        ArrayList<String> sortedMessages = new ArrayList<String>(errorMessages);
        Collections.sort(sortedMessages);
        return StringUtils.collectionToDelimitedString(sortedMessages, " ");
    }
}