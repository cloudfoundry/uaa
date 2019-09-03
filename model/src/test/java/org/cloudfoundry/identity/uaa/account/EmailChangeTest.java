package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.test.JsonTranslation;
import org.junit.jupiter.api.BeforeEach;

class EmailChangeTest extends JsonTranslation<EmailChange> {

    @BeforeEach
    void setUp() {
        EmailChange subject = new EmailChange();
        subject.setClientId("aaaa");
        subject.setEmail("bbbb");
        subject.setUserId("cccc");

        super.setUp(subject, EmailChange.class, WithAllNullFields.EXPECT_NULLS_IN_JSON);
    }

}