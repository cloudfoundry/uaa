package org.cloudfoundry.identity.uaa.user;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class UserInfoTest {

    @Nested
    class Equals {

        @Test
        @SuppressWarnings("java:S5863")
        void expectTrueWhenBothUserInfoObjectsAreSame() {
            UserInfo userInfo = new UserInfo();
            assertThat(userInfo).isEqualTo(userInfo);
        }

        @Test
        void expectFalseWhenUserInfoIsComparedWithOtherObject() {
            UserInfo userInfo = new UserInfo();
            assertThat(new Object()).isNotEqualTo(userInfo);
        }

        @Test
        void expectTrueWhenBothUserInfoWithoutAnyRole() {
            UserInfo u1 = new UserInfo();
            UserInfo u2 = new UserInfo();
            assertThat(u2).isEqualTo(u1);
        }

        @Test
        void expectFalseWhenOnlyOneUserInfoHasRole() {
            UserInfo u1 = userInfoWithRoles(List.of("group1"));
            UserInfo u2 = new UserInfo();
            assertThat(u2).isNotEqualTo(u1);
        }

        @Test
        void expectTrueWhenBothUserInfoHaveSameRole() {
            UserInfo u1 = userInfoWithRoles(List.of("group1"));
            UserInfo u2 = userInfoWithRoles(List.of("group1"));
            assertThat(u2).isEqualTo(u1);
        }

        @Test
        void expectFalseWhenBothUserInfoHaveDifferentRoles() {
            UserInfo u1 = userInfoWithRoles(List.of("group1"));
            UserInfo u2 = userInfoWithRoles(List.of("group2"));
            assertThat(u2).isNotEqualTo(u1);
        }

        @Test
        void expectFalseWhenBothUserInfoHaveMultipleRolesAndFewAreCommon() {
            UserInfo u1 = userInfoWithRoles(List.of("group1", "group2", "group3"));
            UserInfo u2 = userInfoWithRoles(List.of("group2", "group3", "group4"));
            assertThat(u2).isNotEqualTo(u1);
        }

        @Test
        void expectTrueWhenBothUserInfoHaveMultipleRolesAndAllAreCommon() {
            UserInfo u1 = userInfoWithRoles(List.of("group1", "group2", "group3"));
            UserInfo u2 = userInfoWithRoles(List.of("group1", "group2", "group3"));
            assertThat(u2).isEqualTo(u1);
        }

        @Test
        void expectEqualsWhenBothUserInfoHaveManyMultipleRolesAndAllAreCommon() {
            // Given
            int count = 10000;
            List<String> roleList1 = new ArrayList<>(count);
            List<String> roleList2 = new ArrayList<>(count);
            for (int i = 1; i <= count; i++) {
                roleList1.add("groups".concat(Integer.toString(i)));
            }
            for (int i = count; 0 < i; i--) {
                roleList2.add("groups".concat(Integer.toString(i)));
            }
            for (int i = 1; i <= count; i++) {
                roleList2.add("groups".concat(Integer.toString(i)));
            }
            // When
            UserInfo u1 = userInfoWithRoles(roleList1);
            UserInfo u2 = userInfoWithRoles(roleList2);
            // Then
            assertThat(u2).isEqualTo(u1);
        }
    }

    private UserInfo userInfoWithRoles(List<String> roles) {
        UserInfo userInfo = new UserInfo();
        userInfo.setRoles(roles);
        return userInfo;
    }
}