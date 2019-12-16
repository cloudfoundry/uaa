/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.impl;

import com.fasterxml.jackson.core.JsonLocation;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class JsonDateDeserializerTest {

    String testDateString = "2017-07-07T23:25:01.297Z";
    Exception exceptionOccured = null;

    @Test
    public void testParsing() throws IOException, ParseException {
        Date d = JsonDateDeserializer.getDate(testDateString, new JsonLocation(null, 22, 0, 0));
        Assert.assertEquals(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").parse(testDateString).getTime(), (long) d.getTime());
    }

    @Test
    public void testParsingParallel() throws InterruptedException {
        Thread[] threadArray = new Thread[1000];
        for (int i = 0; i < 1000; i++) {

            threadArray[i] = new Thread(() -> {
                try {
                    Date d = JsonDateDeserializer.getDate(testDateString, new JsonLocation(null, 22, 0, 0));
                    if(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").parse(testDateString).getTime() != d.getTime())
                    {
                        throw new Exception("Unexpected date");
                    }
                } catch (Exception e) {
                    exceptionOccured = e;
                }
            });
        }
        for (int i = 0; i < 1000; i++) {
            threadArray[i].start();
        }
        for (int i = 0; i < 1000; i++) {
            threadArray[i].join();
        }
        Assert.assertNull(exceptionOccured);
    }

}
