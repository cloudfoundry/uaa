package org.cloudfoundry.identity.uaa.user;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UaaUserPrototypeTest {

    @Test
    void getPassword() {
        UaaUserPrototype prototype = new UaaUserPrototype()
                .withPassword("pass");
        assertThat(prototype.getPassword()).isEqualTo("pass");
    }

    @Test
    void getUserWithId() {
        UaaUserPrototype prototype = new UaaUserPrototype()
                .withUsername("name")
                .withEmail("email")
                .withPassword("pass");
        UaaUser userWithId = new UaaUser(prototype).id("new-id");
        assertThat(userWithId.getId()).isEqualTo("new-id");
    }
}