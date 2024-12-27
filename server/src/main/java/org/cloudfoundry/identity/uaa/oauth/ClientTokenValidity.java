package org.cloudfoundry.identity.uaa.oauth;

public interface ClientTokenValidity {
    Integer getValiditySeconds(String clientId);

    Integer getZoneValiditySeconds();
}
