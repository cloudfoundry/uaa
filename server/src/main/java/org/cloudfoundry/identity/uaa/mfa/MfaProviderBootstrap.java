package org.cloudfoundry.identity.uaa.mfa;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.EmptyResultDataAccessException;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class MfaProviderBootstrap implements InitializingBean {
    private List<MfaProvider> mfaProviders = new ArrayList<>();
    private MfaProviderProvisioning provisioning;

    public MfaProviderBootstrap(MfaProviderProvisioning provisioning) {
        this.provisioning = provisioning;
    }

    @Override
    public void afterPropertiesSet() {
        for(MfaProvider provider : mfaProviders) {
            MfaProvider existing;
            try {
                existing = provisioning.retrieveByName(provider.getName(), "uaa");
            } catch (EmptyResultDataAccessException x){
                provisioning.create(provider, "uaa");
                continue;
            }

            provider.setId(existing.getId());
            provider.setCreated(existing.getCreated());
            provider.setLastModified(new Date(System.currentTimeMillis()));
            provisioning.update(provider, "uaa");
        }
    }

    public List<MfaProvider> getMfaProviders() {
        return mfaProviders;
    }

    public void setMfaProviders(Map<String, Map<String, Object>> mfaProviderYaml) {
        mfaProviders.clear();
        if (mfaProviderYaml == null) {
            return;
        }
        for(Map.Entry<String,Map<String, Object>> mfaProvider : mfaProviderYaml.entrySet()) {
            String name  = mfaProvider.getKey();
            String type = (String) mfaProvider.getValue().get("type");

            MfaProvider def = new MfaProvider();
            def.setType(MfaProvider.MfaProviderType.forValue(type));
            def.setName(name);
            def.setIdentityZoneId("uaa");

            if(def.getType() == MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR) {
                Map<String, Object> config = (Map<String, Object>) mfaProvider.getValue().get("config");
                String providerDescription = (String) config.get("providerDescription");
                Integer digits = (Integer) config.get("digits");
                Integer duration = (Integer) config.get("duration");
                String algorithm = (String) config.get("algorithm");
                String issuer = (String) config.get("issuer");

                GoogleMfaProviderConfig defGoogleConfig = new GoogleMfaProviderConfig();
                defGoogleConfig.setIssuer(issuer);
                defGoogleConfig.setProviderDescription(providerDescription);
                def.setConfig(defGoogleConfig);
            }

            mfaProviders.add(def);
        }
    }
}
