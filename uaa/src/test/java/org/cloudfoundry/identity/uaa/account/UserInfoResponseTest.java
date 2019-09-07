package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.test.JsonTranslation;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class UserInfoResponseTest extends JsonTranslation<UserInfoResponse> {

    @BeforeEach
    void setUp() {
        UserInfoResponse subject = new UserInfoResponse();
        subject.setUserId("aaaa");
        subject.setUserName("bbbb");
        subject.setGivenName("cccc");
        subject.setFamilyName("dddd");
        subject.setPhoneNumber("eeee");
        subject.setEmail("ffff");
        subject.setEmailVerified(false);
        subject.setPreviousLogonSuccess(9876L);
        Map<String, List<String>> userAttributes = new HashMap<>();
        userAttributes.put("a", Arrays.asList("b", "c"));
        userAttributes.put("d", Arrays.asList("e", "f"));
        subject.setUserAttributes(userAttributes);
        subject.setRoles(Arrays.asList("x", "y", "z"));

        super.setUp(subject, UserInfoResponse.class, WithAllNullFields.EXPECT_NULLS_IN_JSON);
    }
}