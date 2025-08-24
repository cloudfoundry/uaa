/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.login.util;

import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;
import org.junit.jupiter.api.Test;

import jakarta.mail.internet.MimeMessage;

import static org.assertj.core.api.Assertions.assertThat;

class FakeJavaMailSenderTest {

    @Test
    void sendDoesntCreateMemoryLeak() {
        FakeJavaMailSender sender = new FakeJavaMailSender();
        sender.setMaxMessages(100);
        MimeMessage m = sender.createMimeMessage();
        for (int i = 0; i < 200; i++) {
            sender.send(m);
        }

        assertThat(sender.getMaxMessages()).isEqualTo(100);
        assertThat(sender.getSentMessages()).hasSize(100);

        MimeMessage lastMessage = sender.createMimeMessage();
        sender.send(lastMessage);
        assertThat(sender.getSentMessages()).hasSize(100);
        assertThat(sender.getSentMessages().get(99).getMessage()).isSameAs(lastMessage);
    }

    @Test
    void doesntStore0Messages() {
        FakeJavaMailSender sender = new FakeJavaMailSender();
        sender.setMaxMessages(-1);
        MimeMessage m = sender.createMimeMessage();
        for (int i = 0; i < 200; i++) {
            sender.send(m);
        }

        assertThat(sender.getMaxMessages()).isZero();
        assertThat(sender.getSentMessages()).isEmpty();
    }
}
