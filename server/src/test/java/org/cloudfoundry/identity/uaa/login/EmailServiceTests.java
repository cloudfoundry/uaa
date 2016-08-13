package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.internet.InternetAddress;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertThat;

public class EmailServiceTests {

    private FakeJavaMailSender mailSender;

    @Before
    public void setUp() throws Exception {
        mailSender = new FakeJavaMailSender();
    }

    @Test
    public void testSendOssMimeMessage() throws Exception {
        EmailService emailService = new EmailService(mailSender, "http://login.example.com/login", null);

        emailService.sendMessage("user@example.com", MessageType.CHANGE_EMAIL, "Test Message", "<html><body>hi</body></html>");

        assertThat(mailSender.getSentMessages(), hasSize(1));
        FakeJavaMailSender.MimeMessageWrapper mimeMessageWrapper = mailSender.getSentMessages().get(0);
        assertThat(mimeMessageWrapper.getFrom(), hasSize(1));
        InternetAddress fromAddress = (InternetAddress) mimeMessageWrapper.getFrom().get(0);
        assertThat(fromAddress.getAddress(), equalTo("admin@login.example.com"));
        assertThat(fromAddress.getPersonal(), equalTo("Cloud Foundry"));
        assertThat(mimeMessageWrapper.getRecipients(Message.RecipientType.TO), hasSize(1));
        assertThat(mimeMessageWrapper.getRecipients(Message.RecipientType.TO).get(0), equalTo((Address) new InternetAddress("user@example.com")));
        assertThat(mimeMessageWrapper.getContentString(), equalTo("<html><body>hi</body></html>"));
    }

    @Test
    public void testSendPivotalMimeMessage() throws Exception {
        IdentityZoneConfiguration defaultConfig = IdentityZoneHolder.get().getConfig();
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName("Best Company");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(branding);
        IdentityZoneHolder.get().setConfig(config);
        try{
            EmailService emailService = new EmailService(mailSender, "http://login.example.com/login", "something-specific@bestcompany.example.com");

            emailService.sendMessage("user@example.com", MessageType.CHANGE_EMAIL, "Test Message", "<html><body>hi</body></html>");

            FakeJavaMailSender.MimeMessageWrapper mimeMessageWrapper = mailSender.getSentMessages().get(0);
            assertThat(mimeMessageWrapper.getFrom(), hasSize(1));
            InternetAddress fromAddress = (InternetAddress) mimeMessageWrapper.getFrom().get(0);
            assertThat(fromAddress.getAddress(), equalTo("something-specific@bestcompany.example.com"));
            assertThat(fromAddress.getPersonal(), equalTo("Best Company"));
        } finally {
            IdentityZoneHolder.get().setConfig(defaultConfig);
        }

    }
}
