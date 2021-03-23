package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.test.JsonTranslation;
import org.junit.jupiter.api.BeforeEach;

class UserAccountStatusTest extends JsonTranslation<UserAccountStatus> {

    @BeforeEach
    void setUp() {
        UserAccountStatus subject = new UserAccountStatus();
        subject.setLocked(true);
        subject.setPasswordChangeRequired(false);

        super.setUp(subject, UserAccountStatus.class, WithAllNullFields.EXPECT_EMPTY_JSON);
    }
}