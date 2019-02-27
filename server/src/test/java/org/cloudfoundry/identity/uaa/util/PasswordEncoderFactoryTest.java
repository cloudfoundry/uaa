package org.cloudfoundry.identity.uaa.util;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.*;

class PasswordEncoderFactoryTest {

    PasswordEncoderFactory subject = new PasswordEncoderFactory();

    @Test
    void get_buildsFakePasswordEncoder_whenRunInUnitTests() {
        assertThat(subject.get(), Matchers.instanceOf(FakePasswordEncoder.class));
    }

    @Test
    void get_buildsRealPasswordEncoder_whenTheFakeClassCannotBeFound_asInProductionOrDevelopmentUaaServers() throws Exception {
        PasswordEncoderFactory spySubject = spy(subject);
        when(spySubject.createFakePasswordEncoder()).thenThrow(ClassNotFoundException.class);

        assertThat(spySubject.get(), Matchers.instanceOf(BCryptPasswordEncoder.class));

        verify(spySubject, times(1)).createFakePasswordEncoder();
        verify(spySubject, times(1)).createRealPasswordEncoder();
    }

}
