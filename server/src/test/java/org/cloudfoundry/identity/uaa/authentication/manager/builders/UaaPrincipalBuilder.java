package org.cloudfoundry.identity.uaa.authentication.manager.builders;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UaaPrincipalBuilder {
    private UaaPrincipal uaaPrincipal = mock(UaaPrincipal.class);

    public static UaaPrincipalBuilder aUaaPrincipal() {
        return new UaaPrincipalBuilder();
    }

    public UaaPrincipal build() {
        return uaaPrincipal;
    }

    public UaaPrincipalBuilder withId(String id) {
        when(uaaPrincipal.getId()).thenReturn(id);
        return this;
    }
}
