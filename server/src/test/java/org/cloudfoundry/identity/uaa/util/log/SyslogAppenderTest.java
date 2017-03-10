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

import org.apache.commons.logging.Log;
import org.apache.log4j.Priority;
import org.apache.log4j.helpers.SyslogQuietWriter;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.NOPLogger;
import org.apache.log4j.spi.NOPLoggerRepository;
import org.hamcrest.Matchers;
import org.hamcrest.core.Every;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.lessThan;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;

public class SyslogAppenderTest {


    private Log log;



    @Test
    public void testLargePacketHeaders() {
        SyslogAppender appender = new SyslogAppender();
        appender.setFacility("USER");
        appender.setThreshold(Priority.DEBUG);
        appender.setSyslogHost("localhost");
        String packetHeader = "TEST HEADER: ";
        appender.setPacketHeader(packetHeader);

        char[] message = new char[3*1024];
        Arrays.fill(message, 0, 1023, 'A');
        Arrays.fill(message, 1024, 1023+1024, 'B');
        Arrays.fill(message, 2048, 1023+2048, 'C');

        SyslogQuietWriter writer = mock(SyslogQuietWriter.class);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        appender.sqw = writer;

        LoggingEvent event = new LoggingEvent(
            "org.apache.commons.logging.impl.Log4JLogger",
            new NOPLogger(new NOPLoggerRepository(), "name"),
            Priority.ERROR,
            new String(message),
            null);

        appender.append(event);
        Mockito.verify(writer, atLeast(4)).write(captor.capture());

        assertThat(captor.getAllValues(), Every.everyItem(Matchers.startsWith(packetHeader)));
        assertThat(captor.getAllValues().stream().map(s -> s.length()).collect(Collectors.toList()), Every.everyItem(lessThan(1019)));

//        log = LogFactory.getLog(getClass());
//        log.error(new String(message));

    }
}