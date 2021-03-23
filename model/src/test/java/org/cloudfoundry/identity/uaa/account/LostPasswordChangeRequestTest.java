package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.test.JsonTranslation;
import org.junit.jupiter.api.BeforeEach;

class LostPasswordChangeRequestTest extends JsonTranslation<LostPasswordChangeRequest> {

    @BeforeEach
    void setUp() {
        LostPasswordChangeRequest lostPasswordChangeRequest = new LostPasswordChangeRequest();
        lostPasswordChangeRequest.setChangeCode("aaaa");
        lostPasswordChangeRequest.setNewPassword("bbbb");

        super.setUp(lostPasswordChangeRequest, LostPasswordChangeRequest.class, WithAllNullFields.EXPECT_EMPTY_JSON);
    }
}