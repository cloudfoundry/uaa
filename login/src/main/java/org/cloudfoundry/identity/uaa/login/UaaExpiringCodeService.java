package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
public class UaaExpiringCodeService implements ExpiringCodeService {
    
    private ExpiringCodeStore codeStore;
    
    public UaaExpiringCodeService(ExpiringCodeStore codeStore) {
        this.codeStore = codeStore;
    }

    @Override
    public String generateCode(Object data, int expiryTime, TimeUnit timeUnit) throws IOException {
        Timestamp expiry = new Timestamp(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(expiryTime, timeUnit));
        String dataJsonString = JsonUtils.writeValueAsString(data);
        return codeStore.generateCode(dataJsonString, expiry).getCode();
    }

    @Override
    public <T> T verifyCode(Class<T> clazz, String code) throws IOException, CodeNotFoundException {
        try {
            ExpiringCode expiringCode = codeStore.retrieveCode(code);
            if (code==null || expiringCode==null) {
                throw new CodeNotFoundException();
            }
            return JsonUtils.readValue(expiringCode.getData(), clazz);
        } catch (JsonUtils.JsonUtilException e) {
            throw new CodeNotFoundException();
        }
    }
    
    @Override
    public Map<String,String> verifyCode(String code) throws IOException, CodeNotFoundException {
        try {
            ExpiringCode expiringCode = codeStore.retrieveCode(code);
            if (expiringCode==null) {
                throw new CodeNotFoundException();
            }
            return JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {
            });
        } catch (JsonUtils.JsonUtilException e) {
            throw new CodeNotFoundException();
        }
    }

}
