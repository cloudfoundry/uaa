package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import org.cloudfoundry.identity.uaa.ratelimiting.core.http.AuthorizationCredentialIdExtractor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CallerIdSupplierByType;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CallerIdSupplierByTypeFactory;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class CallerIdSupplierByTypeFactoryFactoryTest {
    private static final String FAKE_JWT = "123.456.789";
    private static final String FAKE_CLIENT_IP = "987.654.321.230";

    RequestInfo mockRequestInfo = Mockito.mock(RequestInfo.class);
    AuthorizationCredentialIdExtractor mockExtractor = Mockito.mock(AuthorizationCredentialIdExtractor.class);

    @Test
    void from() {
        checkNoCredentialIdExtractor(CallerIdSupplierByTypeFactoryFactory.from(null));
        checkWithCredentialIdExtractor(CallerIdSupplierByTypeFactoryFactory.from(mockExtractor));
    }

    private void checkNoCredentialIdExtractor(CallerIdSupplierByTypeFactory factory) {
        assertThat(factory.getClass().getSimpleName()).isEqualTo("FactoryNoCredentialIdExtractor");
        CallerIdSupplierByType callerIdSupplier = checkRequestInfoPaths(factory);
        assertThat(callerIdSupplier.getClass().getSimpleName()).isEqualTo("NoCredentialIdExtractor");

        assertThat(callerIdSupplier.getCallerCredentialsID()).isNull();
    }

    private void checkWithCredentialIdExtractor(CallerIdSupplierByTypeFactory factory) {
        when(mockExtractor.mapAuthorizationToCredentialsID(any())).thenReturn(FAKE_JWT);

        assertThat(factory.getClass().getSimpleName()).isEqualTo("FactoryWithCredentialIdExtractor");
        CallerIdSupplierByType callerIdSupplier = checkRequestInfoPaths(factory);
        assertThat(callerIdSupplier.getClass().getSimpleName()).isEqualTo("WithCredentialIdExtractor");

        assertThat(callerIdSupplier.getCallerCredentialsID()).isEqualTo(FAKE_JWT);
    }

    private CallerIdSupplierByType checkRequestInfoPaths(CallerIdSupplierByTypeFactory factory) {
        CallerIdSupplierByType callerIdSupplier = factory.from(null);
        assertThat(callerIdSupplier).isSameAs(CallerIdSupplierByTypeFactory.NULL_REQUEST_INFO);
        assertThat(callerIdSupplier.getCallerCredentialsID()).isNull();
        assertThat(callerIdSupplier.getCallerRemoteAddressID()).isNull();

        callerIdSupplier = factory.from(mockRequestInfo);
        when(mockRequestInfo.getAuthorizationHeader()).thenReturn("Bearer " + FAKE_JWT);
        when(mockRequestInfo.getClientIP()).thenReturn(FAKE_CLIENT_IP);

        assertThat(callerIdSupplier.getCallerRemoteAddressID()).isEqualTo(FAKE_CLIENT_IP);

        return callerIdSupplier;
    }
}