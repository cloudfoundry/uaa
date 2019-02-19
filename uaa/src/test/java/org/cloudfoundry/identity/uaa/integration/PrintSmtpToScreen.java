/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.integration;

import java.util.Iterator;

import com.dumbster.smtp.SimpleSmtpServer;
import com.dumbster.smtp.SmtpMessage;

public class PrintSmtpToScreen {

    public static void main(String... args) throws Exception {
        final SimpleSmtpServer server = SimpleSmtpServer.start(2525);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Stopping SMTP server");
            server.stop();
        }));

        while (!server.isStopped()) {
            Iterator iterator = server.getReceivedEmail();
            while (iterator.hasNext()) {
                SmtpMessage m = (SmtpMessage) iterator.next();
                iterator.remove();
                System.out.println(m.getBody());
            }
            Thread.sleep(250);
        }
    }
}
