package org.cloudfoundry.identity.uaa.provider.token;

import java.util.HashMap;
import java.util.Map;

import org.springframework.util.Base64Utils;

import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;
import com.ge.predix.pki.device.spi.PublicKeyNotFoundException;

public class MockPublicKeyProvider implements DevicePublicKeyProvider {

    Map<String, String> publicKeys = new HashMap<>();
    public static final String DEVICE10 = "d10";
    
    public MockPublicKeyProvider() {
        //no test cases use tenant id for now
        this.publicKeys.put(DEVICE10, TestKeys.TOKEN_VERIFYING_KEY);
    }
    
    @Override
    public String getPublicKey(String tenantId, String deviceId) throws PublicKeyNotFoundException {
        
        String key = publicKeys.get(deviceId);
        
        if (null == key) {
            throw new PublicKeyNotFoundException();
        } else {
            // base64url encode this public key to replicate how real provider returns the key
            return Base64Utils.encodeToString(key.getBytes());
        }
    }

}
