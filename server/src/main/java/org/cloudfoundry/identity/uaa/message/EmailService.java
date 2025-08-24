package org.cloudfoundry.identity.uaa.message;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.zone.MergedZoneBrandingInformation;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.mail.Address;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.io.UnsupportedEncodingException;

public class EmailService implements MessageService {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private JavaMailSender mailSender;
    private final String fromAddress;
    private final IdentityZoneManager identityZoneManager;

    public EmailService(JavaMailSender mailSender, String loginUrl, String fromAddress, IdentityZoneManager identityZoneManager) {
        this.mailSender = mailSender;
        this.identityZoneManager = identityZoneManager;

        // if we are provided a from address, use that, if not, fall back to default based on loginUrl
        if (fromAddress != null && !fromAddress.isEmpty()) {
            this.fromAddress = fromAddress;
        } else {
            String host = UriComponentsBuilder.fromUriString(loginUrl).build().getHost();
            this.fromAddress = "admin@" + host;
        }
    }

    public JavaMailSender getMailSender() {
        return mailSender;
    }

    public void setMailSender(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    private Address[] getSenderAddresses() throws UnsupportedEncodingException {
        String name;
        if (identityZoneManager.isCurrentZoneUaa()) {
            String companyName = MergedZoneBrandingInformation.resolveBranding().getCompanyName();
            name = StringUtils.hasText(companyName) ? companyName : "Cloud Foundry";
        } else {
            name = identityZoneManager.getCurrentIdentityZone().getName();
        }

        return new Address[]{new InternetAddress(fromAddress, name)};
    }

    @Override
    public void sendMessage(String email, MessageType messageType, String subject, String htmlContent) {
        MimeMessage message = mailSender.createMimeMessage();
        try {
            message.addFrom(getSenderAddresses());
            message.addRecipients(Message.RecipientType.TO, email);
            message.setSubject(subject);
            message.setContent(htmlContent, "text/html");
        } catch (MessagingException | UnsupportedEncodingException e) {
            logger.error("Exception raised while sending message to {}", email, e);
        }

        mailSender.send(message);
    }
}
