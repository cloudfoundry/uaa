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

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactory;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.Security;

import static java.util.Collections.EMPTY_MAP;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.certificate1;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.key1;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.passphrase1;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class IdentityZoneHolderTest {

    @BeforeEach
    void setUp() {
        IdentityZoneHolder.clear();
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
    class WhenZoneIsUaa {
        @BeforeEach
        void setUp() {
            IdentityZoneHolder.set(IdentityZone.getUaa());
        }

        @Test
        void isUaa() {
            assertThat(IdentityZoneHolder.isUaa(), is(true));
        }

        @Test
        void getSamlSPKeyManager() {
            KeyManager expected = SamlKeyManagerFactory.getKeyManager(IdentityZoneHolder.getUaaZone().getConfig().getSamlConfig());
            KeyManager actual = IdentityZoneHolder.getSamlSPKeyManager();

            assertThat(actual, is(expected));
        }
    }

    @Nested
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

        @Test
        void getSamlSPKeyManager() {
            Security.addProvider(new BouncyCastleProvider());
            IdentityZoneConfiguration mockIdentityZoneConfiguration = mock(IdentityZoneConfiguration.class);
            when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);

            SamlConfig samlConfig = new SamlConfig();
            samlConfig.setKeys(EMPTY_MAP);
            samlConfig.addAndActivateKey("activeKeyId", new SamlKey(key1, passphrase1, certificate1));
            when(mockIdentityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);

            KeyManager expected = SamlKeyManagerFactory.getKeyManager(samlConfig);
            KeyManager actual = IdentityZoneHolder.getSamlSPKeyManager();

            assertThat(actual.getDefaultCredential().getPrivateKey().getEncoded(),
                    is(expected.getDefaultCredential().getPrivateKey().getEncoded()));
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
            assertThat(IdentityZoneHolder.get(), is(IdentityZone.getUaa()));
        }

        @Test
        void getUaaZone() {
            assertThat(IdentityZoneHolder.getUaaZone(), is(IdentityZone.getUaa()));
        }
    }

    @Nested
    class WithJdbcProvisioning {
        private IdentityZoneProvisioning mockIdentityZoneProvisioning;
        private IdentityZone mockIdentityZone;

        @BeforeEach
        void setUp() {
            mockIdentityZoneProvisioning = mock(IdentityZoneProvisioning.class);
            mockIdentityZone = mock(IdentityZone.class);
            when(mockIdentityZoneProvisioning.retrieve(anyString())).thenReturn(mockIdentityZone);
            IdentityZoneHolder.setProvisioning(mockIdentityZoneProvisioning);
        }

        @Test
        void initializer() {
            assertThat(IdentityZoneHolder.get(), is(mockIdentityZone));
            verify(mockIdentityZoneProvisioning).retrieve("uaa");
        }

        @Test
        void getUaaZone() {
            assertThat(IdentityZoneHolder.getUaaZone(), is(mockIdentityZone));
            verify(mockIdentityZoneProvisioning).retrieve("uaa");
        }
    }

    @Test
    void deserialize() {
        final String sampleIdentityZone = getResourceAsString("SampleIdentityZone.json");

        JsonUtils.readValue(sampleIdentityZone, IdentityZone.class);
    }

    private String getResourceAsString(String fileName) {
        try {
            return IOUtils.toString(getClass().getResourceAsStream(fileName), Charset.defaultCharset());
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private static ThreadLocal<KeyManager> getKeyManagerThreadLocal() {
        return (ThreadLocal<KeyManager>)
                ReflectionTestUtils.getField(IdentityZoneHolder.class, "KEY_MANAGER_THREAD_LOCAL");
    }

}
