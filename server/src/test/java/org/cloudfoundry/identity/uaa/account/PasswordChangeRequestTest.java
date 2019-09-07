package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.test.JsonTranslation;
import org.junit.jupiter.api.BeforeEach;

class PasswordChangeRequestTest extends JsonTranslation<PasswordChangeRequest> {

    @BeforeEach
    void setUp() {
        PasswordChangeRequest subject = new PasswordChangeRequest();
        subject.setOldPassword("aaaa");
        subject.setPassword("bbbb");

        super.setUp(subject, PasswordChangeRequest.class, WithAllNullFields.EXPECT_EMPTY_JSON);
    }
}