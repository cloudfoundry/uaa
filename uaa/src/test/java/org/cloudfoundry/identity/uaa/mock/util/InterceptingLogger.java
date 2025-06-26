package org.cloudfoundry.identity.uaa.mock.util;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.slf4j.helpers.SubstituteLogger;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class InterceptingLogger extends SubstituteLogger {
    private final List<String> messages = new ArrayList<>();

    public InterceptingLogger() {
        super("InterceptingLogger", new LinkedList<>(), true);
    }

    @Override
    public void info(String message) {
        messages.add(message);
    }

    public void reset() {
        messages.clear();
    }

    public String getMessageAtIndex(int messageIndex) {
        return messages.get(messageIndex);
    }

    public String getFirstLogMessageOfType(AuditEventType type) {
        return messages.stream().filter(msg -> msg.startsWith(type.toString() + " ")).findFirst().orElse(null);
    }

    public int getMessageCount() {
        return messages.size();
    }

    public String getLatestMessage() {
        if (messages.isEmpty()) {
            return null;
        }
        return messages.getLast();
    }
}
