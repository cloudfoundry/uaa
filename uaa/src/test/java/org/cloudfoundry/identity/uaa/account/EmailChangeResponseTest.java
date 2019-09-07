package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.test.JsonTranslation;
import org.junit.jupiter.api.BeforeEach;

class EmailChangeResponseTest extends JsonTranslation<EmailChangeResponse> {

    @BeforeEach
    void setUp() {
        EmailChangeResponse subject = new EmailChangeResponse();
        subject.setUsername("aaaa");
        subject.setUserId("bbbb");
        subject.setRedirectUrl("cccc");
        subject.setEmail("dddd");

        super.setUp(subject, EmailChangeResponse.class);
    }
}