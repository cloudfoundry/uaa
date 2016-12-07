/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.util.log;

import org.apache.log4j.Layout;
import org.apache.log4j.spi.LoggingEvent;

public class LineAwareLayout extends Layout {
    private Layout messageLayout;
    private Layout lineLayout;

    public LineAwareLayout() {
    }

    public LineAwareLayout(Layout lineLayout) {
        this(lineLayout, null);
    }

    public LineAwareLayout(Layout lineLayout, Layout messageLayout) {
        this.messageLayout = messageLayout;
        this.lineLayout = lineLayout;
    }

    @Override
    public String format(LoggingEvent event) {
        if(lineLayout == null) { return messageLayout == null ? event.getRenderedMessage() : messageLayout.format(event); }

        String message = event.getRenderedMessage();

        String[] lines;
        String[] throwable;
        if(messageLayout == null && (throwable = event.getThrowableStrRep()) != null) {
            lines = throwable;
        } else if(message != null) {
            lines = message.split("\r?\n");
        } else {
            lines = new String[0];
        }

        StringBuffer strBuf = new StringBuffer();
        for (String line : lines) {
            String formattedLine = lineLayout.format(replaceEventMessageWithoutThrowable(event, line));
            strBuf.append(formattedLine);
        }

        String formattedLines = strBuf.toString();
        if (messageLayout == null) return formattedLines;
        return messageLayout.format(replaceEventMessage(event, formattedLines));
    }

    @Override
    public boolean ignoresThrowable() {
        return messageLayout != null && messageLayout.ignoresThrowable();
    }

    @Override
    public void activateOptions() {
        if(lineLayout != null) { lineLayout.activateOptions(); }
        if (messageLayout != null) { messageLayout.activateOptions(); }
    }

    public Layout getLineLayout() {
        return lineLayout;
    }

    public void setLineLayout(Layout lineLayout) {
        this.lineLayout = lineLayout;
    }

    public Layout getMessageLayout() {
        return messageLayout;
    }

    public void setMessageLayout(Layout messageLayout) {
        this.messageLayout = messageLayout;
    }

    private static LoggingEvent replaceEventMessageWithoutThrowable(LoggingEvent event, String message) {
        return new LoggingEvent(event.getFQNOfLoggerClass(), event.getLogger(), event.getTimeStamp(), event.getLevel(), message, event.getThreadName(), null, event.getNDC(), event.getLocationInformation(), event.getProperties());
    }

    private static LoggingEvent replaceEventMessage(LoggingEvent event, String message) {
        return new LoggingEvent(event.getFQNOfLoggerClass(), event.getLogger(), event.getTimeStamp(), event.getLevel(), message, event.getThreadName(), event.getThrowableInformation(), event.getNDC(), event.getLocationInformation(), event.getProperties());
    }
}
