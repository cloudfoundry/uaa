
package org.cloudfoundry.identity.uaa.scim.exception;

import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Checked exception signalling an invalid password.
 * 
 * @author Dave Syer
 * 
 */
public class InvalidPasswordException extends ScimException {

    private final List<String> errorMessages;

    public InvalidPasswordException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
        errorMessages = Collections.singletonList(message);
    }

    public InvalidPasswordException(List<String> errorMessages) {
        super(StringUtils.collectionToDelimitedString(errorMessages, ","), HttpStatus.BAD_REQUEST);
        this.errorMessages = errorMessages;
    }

    public InvalidPasswordException(String message, HttpStatus httpStatus) {
        super(message, httpStatus);
        errorMessages = Collections.singletonList(message);
    }

    public List<String> getErrorMessages() {
        return errorMessages;
    }

    public String getMessagesAsOneString() {
        ArrayList<String> sortedMessages = new ArrayList<String>(errorMessages);
        Collections.sort(sortedMessages);
        return StringUtils.collectionToDelimitedString(sortedMessages, " ");
    }

    @Override
    public String getMessage() { return getMessagesAsOneString(); }
}
