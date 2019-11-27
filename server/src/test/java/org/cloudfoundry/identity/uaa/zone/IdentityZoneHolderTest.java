/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactory;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.*;

@ExtendWith(PollutionPreventionExtension.class)
class IdentityZoneHolderTest {

    private SamlKeyManagerFactory mockSamlKeyManagerFactory;

    @BeforeEach
    void setUp() {
        mockSamlKeyManagerFactory = mock(SamlKeyManagerFactory.class);
        setSamlKeyManagerFactory(mockSamlKeyManagerFactory);
    }

    @AfterAll
    static void tearDown() {
        setSamlKeyManagerFactory(new SamlKeyManagerFactory());
    }

    @Test
    void set() {
        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        getKeyManagerThreadLocal().set(mock(KeyManager.class));

        IdentityZoneHolder.set(mockIdentityZone);

        assertThat(IdentityZoneHolder.get(), is(mockIdentityZone));
        assertThat(getKeyManagerThreadLocal().get(), is(nullValue()));
    }

    @Test
    void get() {
        IdentityZone mockIdentityZone = mock(IdentityZone.class);

        IdentityZoneHolder.set(mockIdentityZone);

        assertThat(IdentityZoneHolder.get(), is(mockIdentityZone));
    }

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    class WhenZoneIsUaa {
        @BeforeEach
        void setUp() {
            IdentityZoneHolder.set(IdentityZone.getUaa());
        }

        @Test
        void isUaa() {
            assertThat(IdentityZoneHolder.isUaa(), is(true));
        }
    }

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    class WhenZoneIsNotUaa {
        private IdentityZone mockIdentityZone;

        @BeforeEach
        void setUp() {
            mockIdentityZone = mock(IdentityZone.class);
            when(mockIdentityZone.getId()).thenReturn("not uaa");
            IdentityZoneHolder.set(mockIdentityZone);
        }

        @Test
        void isUaa() {
            assertThat(IdentityZoneHolder.isUaa(), is(false));
        }
    }

    @Nested
    class WithNullProvisioning {
        @BeforeEach
        void setUp() {
            IdentityZoneHolder.setProvisioning(null);
        }

        @Test
        void initializer() {
            IdentityZoneHolder.clear();
            assertThat(IdentityZoneHolder.get(), is(IdentityZone.getUaa()));
        }

        @Test
        void getUaaZone() {
            assertThat(IdentityZoneHolder.getUaaZone(), is(IdentityZone.getUaa()));
        }

        @Test
        void getSamlSPKeyManager_WhenSecondCallWorks() {
            IdentityZone mockIdentityZone = mock(IdentityZone.class);
            IdentityZoneHolder.set(mockIdentityZone);

            IdentityZoneConfiguration mockIdentityZoneConfiguration = mock(IdentityZoneConfiguration.class);
            when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);

            SamlConfig mockSamlConfig = mock(SamlConfig.class);
            when(mockIdentityZoneConfiguration.getSamlConfig()).thenReturn(mockSamlConfig);

            KeyManager expectedKeyManager = mock(KeyManager.class);
            when(mockSamlKeyManagerFactory.getKeyManager(any()))
                    .thenReturn(null)
                    .thenReturn(expectedKeyManager);

            // Call several times! The value is cached in KEY_MANAGER_THREAD_LOCAL
            assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
            assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
            assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
            assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
            assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));

            verify(mockSamlKeyManagerFactory).getKeyManager(mockSamlConfig);
            verify(mockSamlKeyManagerFactory, times(2)).getKeyManager(any());
        }
    }

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    class WithJdbcProvisioning {
        private IdentityZoneProvisioning mockIdentityZoneProvisioning;
        private IdentityZone mockIdentityZoneFromProvisioning;

        @BeforeEach
        void setUp() {
            mockIdentityZoneProvisioning = mock(IdentityZoneProvisioning.class);
            mockIdentityZoneFromProvisioning = mock(IdentityZone.class);
            when(mockIdentityZoneProvisioning.retrieve(anyString())).thenReturn(mockIdentityZoneFromProvisioning);
            IdentityZoneHolder.setProvisioning(mockIdentityZoneProvisioning);
        }

        @Test
        void initializer() {
            IdentityZoneHolder.clear();
            assertThat(IdentityZoneHolder.get(), is(mockIdentityZoneFromProvisioning));
            verify(mockIdentityZoneProvisioning).retrieve("uaa");
        }

        @Test
        void getUaaZone() {
            assertThat(IdentityZoneHolder.getUaaZone(), is(mockIdentityZoneFromProvisioning));
            verify(mockIdentityZoneProvisioning).retrieve("uaa");
        }

        @Test
        void getSamlSPKeyManager_WhenSecondCallWorks() {
            IdentityZoneConfiguration mockIdentityZoneConfigurationFromProvisioning = mock(IdentityZoneConfiguration.class);
            when(mockIdentityZoneFromProvisioning.getConfig()).thenReturn(mockIdentityZoneConfigurationFromProvisioning);

            SamlConfig mockSamlConfigFromProvisioning = mock(SamlConfig.class);
            when(mockIdentityZoneConfigurationFromProvisioning.getSamlConfig()).thenReturn(mockSamlConfigFromProvisioning);

            IdentityZone mockIdentityZone = mock(IdentityZone.class);
            IdentityZoneConfiguration mockIdentityZoneConfiguration = mock(IdentityZoneConfiguration.class);
            SamlConfig mockSamlConfig = mock(SamlConfig.class);
            when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);
            when(mockIdentityZoneConfiguration.getSamlConfig()).thenReturn(mockSamlConfig);
            when(mockSamlKeyManagerFactory.getKeyManager(mockSamlConfig))
                    .thenReturn(null);
            IdentityZoneHolder.set(mockIdentityZone);

            KeyManager expectedKeyManager = mock(KeyManager.class);
            when(mockSamlKeyManagerFactory.getKeyManager(mockSamlConfigFromProvisioning))
                    .thenReturn(expectedKeyManager);

            // Call several times! The value is cached in KEY_MANAGER_THREAD_LOCAL
            assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
            assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
            assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
            assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
            assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));

            InOrder inOrder = inOrder(mockSamlKeyManagerFactory);

            inOrder.verify(mockSamlKeyManagerFactory).getKeyManager(mockSamlConfig);
            inOrder.verify(mockSamlKeyManagerFactory).getKeyManager(mockSamlConfigFromProvisioning);
            verify(mockSamlKeyManagerFactory, times(2)).getKeyManager(any());
        }
    }

    @Test
    void getSamlSPKeyManager_WhenKeyManagerIsNotNull() {
        KeyManager expectedKeyManager = mock(KeyManager.class);
        getKeyManagerThreadLocal().set(expectedKeyManager);

        // Call several times! The value is cached in KEY_MANAGER_THREAD_LOCAL
        assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
        assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
        assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
        assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
        assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));

        verify(mockSamlKeyManagerFactory, never()).getKeyManager(any());
    }

    @Test
    void getSamlSPKeyManager_WhenFirstCallWorks() {
        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        IdentityZoneHolder.set(mockIdentityZone);

        IdentityZoneConfiguration mockIdentityZoneConfiguration = mock(IdentityZoneConfiguration.class);
        when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);

        SamlConfig mockSamlConfig = mock(SamlConfig.class);
        when(mockIdentityZoneConfiguration.getSamlConfig()).thenReturn(mockSamlConfig);

        KeyManager expectedKeyManager = mock(KeyManager.class);
        when(mockSamlKeyManagerFactory.getKeyManager(any())).thenReturn(expectedKeyManager);

        // Call several times! The value is cached in KEY_MANAGER_THREAD_LOCAL
        assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
        assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
        assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
        assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));
        assertThat(IdentityZoneHolder.getSamlSPKeyManager(), is(expectedKeyManager));

        verify(mockSamlKeyManagerFactory).getKeyManager(mockSamlConfig);
        verify(mockSamlKeyManagerFactory, times(1)).getKeyManager(any());
    }

    @Test
    void getCurrentZoneId() {
        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        String expectedId = UUID.randomUUID().toString();
        when(mockIdentityZone.getId()).thenReturn(expectedId);
        IdentityZoneHolder.set(mockIdentityZone);

        assertThat(IdentityZoneHolder.getCurrentZoneId(), is(expectedId));
    }

    private static void setSamlKeyManagerFactory(
            SamlKeyManagerFactory samlKeyManagerFactory) {
        ReflectionTestUtils.setField(
                IdentityZoneHolder.class,
                "samlKeyManagerFactory",
                samlKeyManagerFactory);
    }

    private static ThreadLocal<KeyManager> getKeyManagerThreadLocal() {
        return (ThreadLocal<KeyManager>)
                ReflectionTestUtils.getField(IdentityZoneHolder.class, "KEY_MANAGER_THREAD_LOCAL");
    }

}
