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

import org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManager;
import org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactory;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

// This class tests a deprecated class, naturally there will be deprecation warnings, suppress them
@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class IdentityZoneHolderTest {

    @Mock
    IdentityZoneProvisioning mockProvisioning;

    @Mock
    private SamlKeyManagerFactory mockSamlKeyManagerFactory;

    @Mock
    IdentityZone mockIdentityZone;

    @Mock
    private SamlKeyManager mockSamlKeyManager;

    @BeforeEach
    void setUp() {
        IdentityZoneHolder.setProvisioning(mockProvisioning);
        IdentityZoneHolder.setSamlKeyManagerFactory(mockSamlKeyManagerFactory);
    }

    // IdentityZoneHolder has a lot of SAML functionality built-in
    // Also, note that it's deprecated and we should migrate the code to use IdentityZoneManager
    @Test
    void set() {
        IdentityZoneHolder.set(mockIdentityZone);
        assertThat(IdentityZoneHolder.get()).isSameAs(mockIdentityZone);
        assertThat(IdentityZoneHolder.getSamlKeyManager()).isNull();
    }

    @Nested
    class WhenZoneIsUaa {
        @BeforeEach
        void setUp() {
            IdentityZoneHolder.set(IdentityZone.getUaa());
        }

        @Test
        void isUaa() {
            assertThat(IdentityZoneHolder.isUaa()).isTrue();
        }
    }

    @Nested
    class InitializerSetUp {
        @Mock
        IdentityZoneProvisioning mockProvisioning2;

        @Mock
        private SamlKeyManagerFactory mockSamlKeyManagerFactory2;

        @Test
        void initializerSetResetValues() {
            IdentityZoneHolder.Initializer initializer = new IdentityZoneHolder.Initializer(mockProvisioning2, mockSamlKeyManagerFactory2);
            assertThat(getIdentityZoneProvisioning()).isSameAs(mockProvisioning2);
            assertThat(getSamlKeyManagerFactory()).isSameAs(mockSamlKeyManagerFactory2);

            initializer.reset();
            assertThat(getIdentityZoneProvisioning()).isNull();
            assertThat(getSamlKeyManagerFactory()).isNull();
        }
    }

    @Nested
    class WhenZoneIsNotUaa {
        @BeforeEach
        void setUp() {
            when(mockIdentityZone.isUaa()).thenReturn(false);
            IdentityZoneHolder.set(mockIdentityZone);
        }

        @Test
        void isUaa() {
            assertThat(IdentityZoneHolder.isUaa()).isFalse();
        }
    }

    @Nested
    class WithNullProvisioning {
        @BeforeEach
        void setUp() {
            IdentityZoneHolder.setProvisioning(null);
        }

        @Test
        void get() {
            IdentityZoneHolder.clear();
            assertThat(IdentityZoneHolder.get()).isEqualTo(IdentityZone.getUaa());
        }

        @Test
        void getUaaZone() {
            assertThat(IdentityZoneHolder.getUaaZone()).isEqualTo(IdentityZone.getUaa());
        }
    }

    @Nested
    class WithJdbcProvisioning {
        private IdentityZone mockIdentityZoneFromProvisioning;

        @BeforeEach
        void setUp() {
            mockIdentityZoneFromProvisioning = mock(IdentityZone.class);
            when(mockProvisioning.retrieve(anyString())).thenReturn(mockIdentityZoneFromProvisioning);
            IdentityZoneHolder.setProvisioning(mockProvisioning);
        }

        @Test
        void initializer() {
            IdentityZoneHolder.clear();
            assertThat(IdentityZoneHolder.get()).isEqualTo(mockIdentityZoneFromProvisioning);
            verify(mockProvisioning).retrieve("uaa");
        }

        @Test
        void getUaaZone() {
            assertThat(IdentityZoneHolder.getUaaZone()).isEqualTo(mockIdentityZoneFromProvisioning);
            verify(mockProvisioning).retrieve("uaa");
        }
    }

    @Test
    void getSamlKeyManager_WhenKeyManagerIsAlreadyCached() {
        getKeyManagerThreadLocal().set(mockSamlKeyManager);

        // Call several times! The value is cached in KEY_MANAGER_THREAD_LOCAL
        for (int i = 0; i < 3; i++) {
            assertThat(IdentityZoneHolder.getSamlKeyManager()).isSameAs(mockSamlKeyManager);
        }
        verify(mockSamlKeyManagerFactory, never()).getKeyManager(any());
    }

    @Test
    void getSamlKeyManager_IsCachedForSubsequentCalls() {
        IdentityZoneHolder.set(mockIdentityZone);

        IdentityZoneConfiguration mockIdentityZoneConfiguration = mock(IdentityZoneConfiguration.class);
        when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);
        SamlConfig mockSamlConfig = mock(SamlConfig.class);
        when(mockIdentityZoneConfiguration.getSamlConfig()).thenReturn(mockSamlConfig);
        when(mockSamlConfig.getKeys()).thenReturn(Map.of("key1", new SamlKey("key1", "passphrase1", "certificate1")));
        when(mockSamlKeyManagerFactory.getKeyManager(mockSamlConfig)).thenReturn(mockSamlKeyManager);

        // Call several times! The value is cached in KEY_MANAGER_THREAD_LOCAL
        for (int i = 0; i < 10; i++) {
            assertThat(IdentityZoneHolder.getSamlKeyManager()).isSameAs(mockSamlKeyManager);
        }

        verify(mockSamlKeyManagerFactory).getKeyManager(mockSamlConfig);
        verify(mockSamlKeyManagerFactory, times(1)).getKeyManager(any());
    }

    @Test
    void getSamlKeyManager_RetryOnNull_CachedForSubsequentCalls() {
        IdentityZoneHolder.set(mockIdentityZone);

        IdentityZoneConfiguration mockIdentityZoneConfiguration = mock(IdentityZoneConfiguration.class);
        when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);
        SamlConfig mockSamlConfig = mock(SamlConfig.class);
        when(mockIdentityZoneConfiguration.getSamlConfig()).thenReturn(mockSamlConfig);
        when(mockSamlConfig.getKeys()).thenReturn(Map.of("key1", new SamlKey("key1", "passphrase1", "certificate1")));
        when(mockSamlKeyManagerFactory.getKeyManager(mockSamlConfig)).thenReturn(null, mockSamlKeyManager);

        assertThat(IdentityZoneHolder.getSamlKeyManager()).isNull();

        // Call several times! The value is cached in KEY_MANAGER_THREAD_LOCAL
        for (int i = 0; i < 10; i++) {
            assertThat(IdentityZoneHolder.getSamlKeyManager()).isSameAs(mockSamlKeyManager);
        }

        verify(mockSamlKeyManagerFactory, times(2)).getKeyManager(any());
    }

    @Test
    void getCurrentZoneId() {
        String expectedId = UUID.randomUUID().toString();
        when(mockIdentityZone.getId()).thenReturn(expectedId);
        IdentityZoneHolder.set(mockIdentityZone);

        assertThat(IdentityZoneHolder.getCurrentZoneId()).isEqualTo(expectedId);
    }

    private static IdentityZoneProvisioning getIdentityZoneProvisioning() {
        return (IdentityZoneProvisioning) ReflectionTestUtils.getField(IdentityZoneHolder.class, "provisioning");
    }

    private static SamlKeyManagerFactory getSamlKeyManagerFactory() {
        return (SamlKeyManagerFactory) ReflectionTestUtils.getField(IdentityZoneHolder.class, "samlKeyManagerFactory");
    }

    @SuppressWarnings("unchecked")
    private static ThreadLocal<SamlKeyManager> getKeyManagerThreadLocal() {
        return (ThreadLocal<SamlKeyManager>) ReflectionTestUtils.getField(IdentityZoneHolder.class, "KEY_MANAGER_THREAD_LOCAL");
    }
}
