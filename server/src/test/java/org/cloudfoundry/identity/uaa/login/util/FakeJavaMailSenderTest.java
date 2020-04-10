package org.cloudfoundry.identity.uaa.login.util;

import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;
import org.junit.Test;

import javax.mail.internet.MimeMessage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

public class FakeJavaMailSenderTest {

    @Test
    public void testSendDoesntCreateMemoryLeak() {
        FakeJavaMailSender sender = new FakeJavaMailSender();
        sender.setMaxMessages(100);
        MimeMessage m = sender.createMimeMessage();
        for (int i=0; i<200; i++) {
            sender.send(m);
        }

        assertEquals(100, sender.getMaxMessages());
        assertEquals(100, sender.getSentMessages().size());

        MimeMessage lastMessage = sender.createMimeMessage();
        sender.send(lastMessage);
        assertEquals(100, sender.getSentMessages().size());
        assertSame(lastMessage, sender.getSentMessages().get(99).getMessage());
    }

    @Test
    public void testDoesntStore0Messages() {
        FakeJavaMailSender sender = new FakeJavaMailSender();
        sender.setMaxMessages(-1);
        MimeMessage m = sender.createMimeMessage();
        for (int i=0; i<200; i++) {
            sender.send(m);
        }

        assertEquals(0, sender.getMaxMessages());
        assertEquals(0, sender.getSentMessages().size());
    }
}