/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login.test;

import org.apache.commons.io.IOUtils;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessagePreparator;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;

public class FakeJavaMailSender implements JavaMailSender {

    private final Session session;
    private final ArrayList<MimeMessageWrapper> sentMessages;

    public FakeJavaMailSender() {
        session = Session.getInstance(new Properties());
        sentMessages = new ArrayList<>();
    }

    @Override
    public MimeMessage createMimeMessage() {
        return new MimeMessage(session);
    }

    @Override
    public MimeMessage createMimeMessage(InputStream inputStream)  {
        throw new UnsupportedOperationException();
    }

    @Override
    public void send(MimeMessage mimeMessage) throws MailException {
        sentMessages.add(new MimeMessageWrapper(mimeMessage));
    }

    @Override
    public void send(MimeMessage[] mimeMessages) throws MailException {
        throw new UnsupportedOperationException();
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

    public ArrayList<MimeMessageWrapper> getSentMessages() {
        return sentMessages;
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
            return IOUtils.toString(mimeMessage.getDataHandler().getInputStream());
        }
    }
}
