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

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.GreenMailUtil;
import com.icegreen.greenmail.util.ServerSetup;
import jakarta.mail.internet.MimeMessage;

public class PrintSmtpToScreen {

    public static void main(String... args) throws Exception {
        GreenMail server = new GreenMail(new ServerSetup(2525, null, ServerSetup.PROTOCOL_SMTP));
        server.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            IO.println("Stopping SMTP server");
            server.stop();
        }));

        int lastCount = 0;
        while (true) {
            MimeMessage[] messages = server.getReceivedMessages();
            for (int i = lastCount; i < messages.length; i++) {
                IO.println(GreenMailUtil.getBody(messages[i]));
            }
            lastCount = messages.length;
            Thread.sleep(250);
        }
    }
}
