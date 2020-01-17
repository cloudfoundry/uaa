package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import javax.mail.Message;
import javax.mail.internet.InternetAddress;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class EmailServiceTests {

    private FakeJavaMailSender mailSender;
    private IdentityZoneManager mockIdentityZoneManager;
    private IdentityZone mockIdentityZone;

    @BeforeEach
    void setUp() {
        mailSender = new FakeJavaMailSender();
        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        mockIdentityZone = mock(IdentityZone.class);

        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);
        when(mockIdentityZoneManager.isCurrentZoneUaa()).thenReturn(true);
        IdentityZoneHolder.set(mockIdentityZone);
    }

    @Test
    void sendOssMimeMessage() throws Exception {
        EmailService emailService = new EmailService(
                mailSender,
                "http://login.example.com/login",
                null,
                mockIdentityZoneManager);

        emailService.sendMessage(
                "user@example.com",
                MessageType.CHANGE_EMAIL,
                "Test Message",
                "<html><body>hi</body></html>");

        assertThat(mailSender.getSentMessages(), hasSize(1));
        FakeJavaMailSender.MimeMessageWrapper mimeMessageWrapper = mailSender.getSentMessages().get(0);
        assertThat(mimeMessageWrapper.getFrom(), hasSize(1));
        InternetAddress fromAddress = (InternetAddress) mimeMessageWrapper.getFrom().get(0);
        assertThat(fromAddress.getAddress(), equalTo("admin@login.example.com"));
        assertThat(fromAddress.getPersonal(), equalTo("Cloud Foundry"));
        assertThat(mimeMessageWrapper.getRecipients(Message.RecipientType.TO), hasSize(1));
        assertThat(mimeMessageWrapper.getRecipients(Message.RecipientType.TO).get(0), equalTo(new InternetAddress("user@example.com")));
        assertThat(mimeMessageWrapper.getContentString(), equalTo("<html><body>hi</body></html>"));
    }

    @Test
    void sendPivotalMimeMessage() throws Exception {
        BrandingInformation mockBrandingInformation = mock(BrandingInformation.class);
        when(mockBrandingInformation.getCompanyName()).thenReturn("Best Company");
        IdentityZoneConfiguration mockIdentityZoneConfiguration = mock(IdentityZoneConfiguration.class);
        when(mockIdentityZoneConfiguration.getBranding()).thenReturn(mockBrandingInformation);
        when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);

        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);

        EmailService emailService = new EmailService(
                mailSender,
                "http://login.example.com/login",
                "something-specific@bestcompany.example.com",
                mockIdentityZoneManager);

        emailService.sendMessage(
                "user@example.com",
                MessageType.CHANGE_EMAIL,
                "Test Message",
                "<html><body>hi</body></html>");

        FakeJavaMailSender.MimeMessageWrapper mimeMessageWrapper = mailSender.getSentMessages().get(0);
        assertThat(mimeMessageWrapper.getFrom(), hasSize(1));
        InternetAddress fromAddress = (InternetAddress) mimeMessageWrapper.getFrom().get(0);
        assertThat(fromAddress.getAddress(), equalTo("something-specific@bestcompany.example.com"));
        assertThat(fromAddress.getPersonal(), equalTo("Best Company"));
    }
}
