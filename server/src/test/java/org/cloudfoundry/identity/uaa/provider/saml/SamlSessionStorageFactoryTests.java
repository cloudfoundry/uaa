package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

@ExtendWith(PollutionPreventionExtension.class)
class SamlSessionStorageFactoryTests {

    private SamlSessionStorageFactory factory;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        factory = new SamlSessionStorageFactory();
        IdentityZoneHolder.clear();
        IdentityZoneHolder.setProvisioning(null);
    }

    @Test
    void get_storage_creates_session() {
        assertNull(request.getSession(false));
        factory.getMessageStorage(request);
        assertNotNull(request.getSession(false));
    }

    @Test
    void disable_message_storage() {
        IdentityZoneHolder.get().getConfig().getSamlConfig().setDisableInResponseToCheck(true);
        assertNull(factory.getMessageStorage(request));
    }

}