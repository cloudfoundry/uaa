package org.cloudfoundry.identity.uaa.provider.token;

import org.springframework.util.Base64Utils;

import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;
import com.ge.predix.pki.device.spi.PublicKeyNotFoundException;

public class MockPublicKeyProvider implements DevicePublicKeyProvider {

    @Override
    public String getPublicKey(String tenantId, String deviceId) throws PublicKeyNotFoundException {
        
     // base64url encode this public key to replicate how real provider returns the key
        return Base64Utils.encodeToString(TestKeys.TOKEN_VERIFYING_KEY.getBytes());
    }

}
