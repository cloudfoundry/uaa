package org.cloudfoundry.identity.uaa.oauth;

import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addSubdomainToUrl;

import java.util.HashMap;
import java.util.Map;
import org.cloudfoundry.identity.uaa.impl.config.LegacyTokenKey;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.util.StringUtils;

public class KeyInfoService {

  private String uaaBaseURL;

  public KeyInfoService(String uaaBaseURL) {
    this.uaaBaseURL = uaaBaseURL;
  }

  public KeyInfo getKey(String keyId) {
    return getKeys().get(keyId);
  }

  public Map<String, KeyInfo> getKeys() {
    IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
    if (config == null
        || config.getTokenPolicy().getKeys() == null
        || config.getTokenPolicy().getKeys().isEmpty()) {
      config = IdentityZoneHolder.getUaaZone().getConfig();
    }

    Map<String, KeyInfo> keys = new HashMap<>();
    for (Map.Entry<String, String> entry : config.getTokenPolicy().getKeys().entrySet()) {
      KeyInfo keyInfo =
          KeyInfoBuilder.build(
              entry.getKey(),
              entry.getValue(),
              addSubdomainToUrl(uaaBaseURL, IdentityZoneHolder.get().getSubdomain()));
      keys.put(entry.getKey(), keyInfo);
    }

    if (keys.isEmpty()) {
      keys.put(LegacyTokenKey.LEGACY_TOKEN_KEY_ID, LegacyTokenKey.getLegacyTokenKeyInfo());
    }

    return keys;
  }

  public KeyInfo getActiveKey() {
    return getKeys().get(getActiveKeyId());
  }

  private String getActiveKeyId() {
    IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
    if (config == null) {
      return IdentityZoneHolder.getUaaZone().getConfig().getTokenPolicy().getActiveKeyId();
    }
    String activeKeyId = config.getTokenPolicy().getActiveKeyId();

    Map<String, KeyInfo> keys;
    if (!StringUtils.hasText(activeKeyId) && (keys = getKeys()).size() == 1) {
      activeKeyId = keys.keySet().stream().findAny().get();
    }

    if (!StringUtils.hasText(activeKeyId)) {
      activeKeyId = IdentityZoneHolder.getUaaZone().getConfig().getTokenPolicy().getActiveKeyId();
    }

    if (!StringUtils.hasText(activeKeyId)) {
      activeKeyId = LegacyTokenKey.LEGACY_TOKEN_KEY_ID;
    }

    return activeKeyId;
  }
}
