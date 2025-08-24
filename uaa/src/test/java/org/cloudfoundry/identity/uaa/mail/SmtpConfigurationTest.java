package org.cloudfoundry.identity.uaa.mail;

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.ServerSetup;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.util.Random;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SmtpConfigurationTest {

    private GreenMail greenMail;
    private int port;

    @BeforeEach
    void setUp() {
        Random random = new Random();
        port = 20_000 + random.nextInt(10_000);
        greenMail = new GreenMail(new ServerSetup(port, null, ServerSetup.PROTOCOL_SMTP));
        greenMail.getManagers().getUserManager().setAuthRequired(true);
        greenMail.setUser("validUser", "validPassword");
        greenMail.start();
    }

    @AfterEach
    void tearDown() {
        greenMail.stop();
    }

    @DefaultTestContext
    @TestPropertySource(properties = {
            "smtp.host=127.0.0.1",
            "smtp.port=3025",
            "smtp.user=badUser",
            "smtp.password=badPassword",
            "smtp.auth=false",
    })
    @DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
    @Nested
    class WithBadUsernameAndPassword {

        @Autowired
        EmailService emailService;

        @BeforeEach
        void setUp() {
            ((JavaMailSenderImpl) emailService.getMailSender()).setPort(port);
        }

        @Test
        void verifyThatBadUserAndBadPasswordCantSendMessages() {
            assertThatThrownBy(() -> emailService.sendMessage("asdf@example.com", MessageType.INVITATION,
                    "email subject", "email html Content"))
                    .isInstanceOf(MailAuthenticationException.class)
                    .rootCause()
                    .isInstanceOf(jakarta.mail.AuthenticationFailedException.class)
                    .hasMessage("535 5.7.8  Authentication credentials invalid\n");
        }
    }

    @DefaultTestContext
    @TestPropertySource(properties = {
            "smtp.host=127.0.0.1",
            "smtp.port=3025",
            "smtp.user=validUser",
            "smtp.password=validPassword",
            "smtp.auth=false",
    })
    @DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
    @Nested
    class WithValidUsernameAndPassword {

        @Autowired
        EmailService emailService;

        @BeforeEach
        void setUp() {
            ((JavaMailSenderImpl) emailService.getMailSender()).setPort(port);
        }

        @Test
        void verifyThatBadUserAndBadPasswordCantSendMessages() {
            assertThatNoException().isThrownBy(() -> emailService.sendMessage("asdf@example.com",
                    MessageType.INVITATION, "email subject", "email html Content"));
        }
    }
}
