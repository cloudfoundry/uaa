package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class ZoneAwareKeyManagerTest {
    @Mock
    SamlKeyManager mockSamlKeyManager;

    private ZoneAwareKeyManager zoneAwareKeyManager;

    @BeforeEach
    void setUp() {
        getKeyManagerThreadLocal().set(mockSamlKeyManager);
        zoneAwareKeyManager = new ZoneAwareKeyManager();
    }

    @AfterAll
    static void afterAll() {
        getKeyManagerThreadLocal().remove();
    }

    @Test
    void getCredential() {
        zoneAwareKeyManager.getCredential("keyName");
        verify(mockSamlKeyManager).getCredential("keyName");
    }

    @Test
    void getDefaultCredential() {
        zoneAwareKeyManager.getDefaultCredential();
        verify(mockSamlKeyManager).getDefaultCredential();
    }

    @Test
    void getDefaultCredentialName() {
        zoneAwareKeyManager.getDefaultCredentialName();
        verify(mockSamlKeyManager).getDefaultCredentialName();
    }

    @Test
    void getAvailableCredentials() {
        zoneAwareKeyManager.getAvailableCredentials();
        verify(mockSamlKeyManager).getAvailableCredentials();
    }

    @Test
    void getAvailableCredentialIds() {
        zoneAwareKeyManager.getAvailableCredentialIds();
        verify(mockSamlKeyManager).getAvailableCredentialIds();
    }

    @SuppressWarnings("unchecked")
    private static ThreadLocal<SamlKeyManager> getKeyManagerThreadLocal() {
        return (ThreadLocal<SamlKeyManager>) ReflectionTestUtils.getField(IdentityZoneHolder.class, "KEY_MANAGER_THREAD_LOCAL");
    }
}
