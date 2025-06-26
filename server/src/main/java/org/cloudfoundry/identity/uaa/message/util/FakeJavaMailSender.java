/*
 * *****************************************************************************
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
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.message.util;

import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.util.StreamUtils;

import jakarta.mail.Address;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

public class FakeJavaMailSender implements JavaMailSender {

    private final Session session;
    private final ArrayList<MimeMessageWrapper> sentMessages;
    private volatile int maxMessages = 1000;

    public FakeJavaMailSender() {
        session = Session.getInstance(new Properties());
        sentMessages = new ArrayList<>();
    }

    public void clearMessage() {
        sentMessages.clear();
    }

    public int getMaxMessages() {
        return maxMessages;
    }

    public void setMaxMessages(int maxMessages) {
        if (maxMessages < 0) {
            this.maxMessages = 0;
        } else {
            this.maxMessages = maxMessages;
        }
    }

    @Override
    public MimeMessage createMimeMessage() {
        return new MimeMessage(session);
    }

    @Override
    public MimeMessage createMimeMessage(InputStream inputStream) {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized void send(MimeMessage mimeMessage) throws MailException {
        if (getMaxMessages() > 0) {
            sentMessages.add(new MimeMessageWrapper(mimeMessage));
        }

        while (sentMessages.size() > getMaxMessages()) {
            sentMessages.removeFirst();
        }
    }

    @Override
    public void send(MimeMessage[] mimeMessages) throws MailException {
        if (mimeMessages != null) {
            for (MimeMessage m : mimeMessages) {
                send(m);
            }
        }
    }

    @Override
    public void send(MimeMessagePreparator mimeMessagePreparator) throws MailException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void send(MimeMessagePreparator[] mimeMessagePreparators) throws MailException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void send(SimpleMailMessage simpleMailMessage) throws MailException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void send(SimpleMailMessage[] simpleMailMessages) throws MailException {
        throw new UnsupportedOperationException();
    }

    public List<MimeMessageWrapper> getSentMessages() {
        return Collections.unmodifiableList(sentMessages);
    }

    public static class MimeMessageWrapper {
        private final MimeMessage mimeMessage;

        public MimeMessageWrapper(MimeMessage mimeMessage) {

            this.mimeMessage = mimeMessage;
        }

        public List<Address> getRecipients(Message.RecipientType recipientType) throws MessagingException {
            return Arrays.asList(mimeMessage.getRecipients(recipientType));
        }

        public List<Address> getFrom() throws MessagingException {
            return Arrays.asList(mimeMessage.getFrom());
        }

        public String getContentString() throws MessagingException, IOException {
            try (InputStream in = mimeMessage.getDataHandler().getInputStream()) {
                return StreamUtils.copyToString(in, StandardCharsets.UTF_8);
            }
        }

        public MimeMessage getMessage() {
            return mimeMessage;
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder("MimeMessageWrapper{");
            try {
                sb.append("From=").append(Arrays.toString(getFrom().toArray()));
                sb.append("; To=").append(Arrays.toString(getRecipients(Message.RecipientType.TO).toArray()));
                sb.append("; Content=").append(getContentString());
            } catch (MessagingException | IOException x) {
                sb.append("Message=").append(mimeMessage);
            }
            sb.append('}');
            return sb.toString();
        }
    }
}
