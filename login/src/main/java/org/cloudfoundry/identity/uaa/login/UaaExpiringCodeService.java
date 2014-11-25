package org.cloudfoundry.identity.uaa.login;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;

import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@Component
public class UaaExpiringCodeService implements ExpiringCodeService {
    
    private ExpiringCodeStore codeStore;
    
    public UaaExpiringCodeService(ExpiringCodeStore codeStore) {
        this.codeStore = codeStore;
    }

    @Override
    public String generateCode(Object data, int expiryTime, TimeUnit timeUnit) throws IOException {
        Timestamp expiry = new Timestamp(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(expiryTime, timeUnit));
        String dataJsonString = new ObjectMapper().writeValueAsString(data);
        return codeStore.generateCode(dataJsonString, expiry).getCode();
    }

    @Override
    public <T> T verifyCode(Class<T> clazz, String code) throws IOException, CodeNotFoundException {
        try {
            ExpiringCode expiringCode = codeStore.retrieveCode(code);
            if (code==null || expiringCode==null) {
                throw new CodeNotFoundException();
            }
            return new ObjectMapper().readValue(expiringCode.getData(), clazz);
        } catch (IOException e) {
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
            return new ObjectMapper().readValue(expiringCode.getData(), new TypeReference<Map<String,String>>() {});
        } catch (IOException e) {
            throw new CodeNotFoundException();
        }
    }

}
