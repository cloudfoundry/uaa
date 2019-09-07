package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.test.JsonTranslation;
import org.junit.jupiter.api.BeforeEach;

class LostPasswordChangeResponseTest extends JsonTranslation<LostPasswordChangeResponse> {

    @BeforeEach
    void setUp() {
        LostPasswordChangeResponse subject = new LostPasswordChangeResponse();
        subject.setLoginCode("aaaa");
        subject.setUserId("bbbb");
        subject.setUsername("cccc");
        subject.setEmail("dddd");

        super.setUp(subject, LostPasswordChangeResponse.class, WithAllNullFields.EXPECT_EMPTY_JSON);
    }
}