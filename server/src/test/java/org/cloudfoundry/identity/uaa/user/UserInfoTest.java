package org.cloudfoundry.identity.uaa.user;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserInfoTest {

    @Nested
    class Equals {

        @Test
        void expectTrueWhenBothUserInfoObjectsAreSame() {
            UserInfo userInfo = new UserInfo();
            assertTrue(userInfo.equals(userInfo));
        }

        @Test
        void expectFalseWhenUserInfoIsComparedWithOtherObject() {
            UserInfo userInfo = new UserInfo();
            assertFalse(userInfo.equals(new Object()));
        }

        @Test
        void expectTrueWhenBothUserInfoWithoutAnyRole() {
            UserInfo u1 = new UserInfo();
            UserInfo u2 = new UserInfo();
            assertTrue(u1.equals(u2));
        }

        @Test
        void expectFalseWhenOnlyOneUserInfoHasRole() {
            UserInfo u1 = userInfoWithRoles(List.of("group1"));
            UserInfo u2 = new UserInfo();
            assertFalse(u1.equals(u2));
        }

        @Test
        void expectTrueWhenBothUserInfoHaveSameRole() {
            UserInfo u1 = userInfoWithRoles(List.of("group1"));
            UserInfo u2 = userInfoWithRoles(List.of("group1"));
            assertTrue(u1.equals(u2));
        }

        @Test
        void expectFalseWhenBothUserInfoHaveDifferentRoles() {
            UserInfo u1 = userInfoWithRoles(List.of("group1"));
            UserInfo u2 = userInfoWithRoles(List.of("group2"));
            assertFalse(u1.equals(u2));
        }

        @Test
        void expectFalseWhenBothUserInfoHaveMultipleRolesAndFewAreCommon() {
            UserInfo u1 = userInfoWithRoles(List.of("group1", "group2", "group3"));
            UserInfo u2 = userInfoWithRoles(List.of("group2", "group3", "group4"));
            assertFalse(u1.equals(u2));
        }

        @Test
        void expectTrueWhenBothUserInfoHaveMultipleRolesAndAllAreCommon() {
            UserInfo u1 = userInfoWithRoles(List.of("group1", "group2", "group3"));
            UserInfo u2 = userInfoWithRoles(List.of("group1", "group2", "group3"));
            assertTrue(u1.equals(u2));
        }

    }

    private UserInfo userInfoWithRoles(List<String> roles) {
        UserInfo userInfo = new UserInfo();
        userInfo.setRoles(roles);
        return userInfo;
    }
}