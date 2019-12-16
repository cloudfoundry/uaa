package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.test.JsonTranslation;
import org.junit.jupiter.api.BeforeEach;

class PasswordResetResponseTest extends JsonTranslation<PasswordResetResponse> {

    @BeforeEach
    void setUp() {
        PasswordResetResponse subject = new PasswordResetResponse();
        subject.setChangeCode("aaaa");
        subject.setUserId("bbbb");

        super.setUp(subject, PasswordResetResponse.class, WithAllNullFields.EXPECT_EMPTY_JSON);
    }
}