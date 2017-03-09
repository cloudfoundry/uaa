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

import org.apache.log4j.Appender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.WriterAppender;
import org.junit.Test;

import java.io.ByteArrayOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class LineAwareLayoutTest {
    private final static String delimiter = " NEWLINE ";

    @Test
    public void messages_over_multiple_lines_are_formatted_per_line() throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        LineAwareLayout lineAwareLayout = new LineAwareLayout();
        lineAwareLayout.setLineLayout(new PatternLayout("%m" + delimiter));
        Appender appender = new WriterAppender(lineAwareLayout, output);

        appender.setName("TestLog");
        appender.setLayout(lineAwareLayout);

        Logger testLogger = LogManager.getLogger("test-logger");
        testLogger.addAppender((appender));
        testLogger.setLevel(Level.INFO);
        String eventMessage = "test message\nwith\nmultiple lines";
        testLogger.info(eventMessage);

        String expectedLog = String.join(delimiter, eventMessage.split("\n")) + delimiter;

        assertEquals(expectedLog, output.toString());
    }

    @Test
    public void logged_exceptions_are_formatted_per_line_when_treating_throwable_as_lines() throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        LineAwareLayout lineAwareLayout = new LineAwareLayout();
        lineAwareLayout.setLineLayout(new PatternLayout("%m" + delimiter));
        Appender appender = new WriterAppender(lineAwareLayout, output);

        appender.setName("TestLog");
        appender.setLayout(lineAwareLayout);
        Logger testLogger = LogManager.getLogger("test-logger");
        testLogger.addAppender(appender);
        testLogger.setLevel(Level.INFO);

        Exception ex = new Exception("SOMETHING BAD HAPPEN\nNO REALLY IT'S VERY BAD\n\ntrust me");
        ex.setStackTrace(new StackTraceElement[]{new StackTraceElement("CLAZZ", "MEETOD", "FEEL", 123)});
        testLogger.info(ex, ex);
        String expectedLog = String.join(delimiter, ex.toString().split("\n")) + delimiter + "\tat CLAZZ.MEETOD(FEEL:123)" + delimiter;

        assertEquals(expectedLog, output.toString());
    }

    @Test
    public void messages_get_the_message_format_applied_after_the_line_format() throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        String extraLine = "\nTHESE NEWLINES SHOULD NOT GET AFFECTED BY THE LINE FORMAT\n";
        LineAwareLayout lineAwareLayout = new LineAwareLayout();
        lineAwareLayout.setLineLayout(new PatternLayout("%m" + delimiter));
        lineAwareLayout.setMessageLayout(new PatternLayout("%m" + extraLine));
        Appender appender = new WriterAppender(lineAwareLayout, output);

        appender.setName("TestLog");
        appender.setLayout(lineAwareLayout);

        Logger testLogger = LogManager.getLogger("test-logger");
        testLogger.addAppender((appender));
        testLogger.setLevel(Level.INFO);
        String eventMessage = "test message\nwith\nmultiple lines";
        testLogger.info(eventMessage);

        String expectedLog = String.join(delimiter, eventMessage.split("\n")) + delimiter
            + extraLine;

        assertEquals(expectedLog, output.toString());
    }

    @Test
    public void ignores_throwable_only_if_message_layout_ignores_throwable() throws Exception {
        LineAwareLayout lineAwareLayout = new LineAwareLayout();

        Layout lineLayout = mock(Layout.class);
        lineAwareLayout.setLineLayout(lineLayout);

        when(lineLayout.ignoresThrowable()).thenReturn(false);
        assertFalse(lineAwareLayout.ignoresThrowable());

        when(lineLayout.ignoresThrowable()).thenReturn(true);
        assertFalse(lineAwareLayout.ignoresThrowable());

        Layout messageLayout = mock(Layout.class);
        lineAwareLayout.setMessageLayout(messageLayout);

        when(messageLayout.ignoresThrowable()).thenReturn(false);
        assertFalse(lineAwareLayout.ignoresThrowable());

        when(messageLayout.ignoresThrowable()).thenReturn(true);
        assertTrue(lineAwareLayout.ignoresThrowable());
    }
}
