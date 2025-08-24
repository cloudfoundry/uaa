package org.cloudfoundry.identity.uaa.zone;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class UserConfigTest {

    @Test
    void defaultConfig() {
        UserConfig userConfig = new UserConfig();
        assertThat(userConfig.getDefaultGroups()).contains("openid");
        assertThat(userConfig.getAllowedGroups()).isNull();       // all groups allowed
        assertThat(userConfig.resultingAllowedGroups()).isNull(); // all groups allowed
    }

    @Test
    void resultingAllowedGroups() {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(List.of("openid"));
        userConfig.setAllowedGroups(List.of("uaa.user"));
        assertThat(userConfig.getDefaultGroups()).isEqualTo(List.of("openid"));
        assertThat(userConfig.getAllowedGroups()).isEqualTo(List.of("uaa.user"));
        assertThat(userConfig.resultingAllowedGroups()).isEqualTo(Set.of("openid", "uaa.user"));
    }

    @Test
    void noDefaultGroups() {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(null);
        userConfig.setAllowedGroups(List.of("uaa.user"));
        assertThat(userConfig.getDefaultGroups()).isNull();
        assertThat(userConfig.getAllowedGroups()).isEqualTo(List.of("uaa.user"));
        assertThat(userConfig.resultingAllowedGroups()).isEqualTo(Set.of("uaa.user"));
    }

    @Test
    void noDefaultAndNoAllowedGroups() {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(null);
        userConfig.setAllowedGroups(null);
        assertThat(userConfig.getDefaultGroups()).isNull();
        assertThat(userConfig.getAllowedGroups()).isNull();       // all groups allowed
        assertThat(userConfig.resultingAllowedGroups()).isNull(); // all groups allowed
    }

    @Test
    void getMaxUsers() {
        UserConfig userConfig = new UserConfig();
        assertThat(userConfig.getMaxUsers()).isEqualTo(-1);
    }

    @Test
    void setMaxUsers() {
        UserConfig userConfig = new UserConfig();
        userConfig.setMaxUsers(100);
        assertThat(userConfig.getMaxUsers()).isEqualTo(100);
    }

    @Test
    void defaultOrigin() {
        UserConfig userConfig = new UserConfig();
        assertThat(userConfig.isAllowOriginLoop()).isTrue();
        assertThat(userConfig.isCheckOriginEnabled()).isFalse();
    }

    @Test
    void originLoop() {
        UserConfig userConfig = new UserConfig();
        assertThat(userConfig.isAllowOriginLoop()).isTrue();
        userConfig.setAllowOriginLoop(false);
        assertThat(userConfig.isCheckOriginEnabled()).isFalse();
    }
}
