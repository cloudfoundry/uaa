package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import org.cloudfoundry.identity.uaa.ratelimiting.core.http.AuthorizationCredentialIdExtractor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CallerIdSupplierByType;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CallerIdSupplierByTypeFactory;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class CallerIdSupplierByTypeFactoryFactoryTest {
    private static final String FAKE_JWT = "123.456.789";
    private static final String FAKE_CLIENT_IP = "987.654.321.230";

    RequestInfo mockRequestInfo = Mockito.mock( RequestInfo.class );
    AuthorizationCredentialIdExtractor mockExtractor = Mockito.mock( AuthorizationCredentialIdExtractor.class );

    @Test
    void from() {
        checkNoCredentialIdExtractor( CallerIdSupplierByTypeFactoryFactory.from( null ) );
        checkWithCredentialIdExtractor( CallerIdSupplierByTypeFactoryFactory.from( mockExtractor ) );
    }

    private void checkNoCredentialIdExtractor( CallerIdSupplierByTypeFactory factory ) {
        assertEquals( "FactoryNoCredentialIdExtractor", factory.getClass().getSimpleName() );
        CallerIdSupplierByType callerIdSupplier = checkRequestInfoPaths( factory );
        assertEquals( "NoCredentialIdExtractor", callerIdSupplier.getClass().getSimpleName() );

        assertNull( callerIdSupplier.getCallerCredentialsID() );
    }

    private void checkWithCredentialIdExtractor( CallerIdSupplierByTypeFactory factory ) {
        when( mockExtractor.mapAuthorizationToCredentialsID( any() ) ).thenReturn( FAKE_JWT );

        assertEquals( "FactoryWithCredentialIdExtractor", factory.getClass().getSimpleName() );
        CallerIdSupplierByType callerIdSupplier = checkRequestInfoPaths( factory );
        assertEquals( "WithCredentialIdExtractor", callerIdSupplier.getClass().getSimpleName() );

        assertEquals( FAKE_JWT, callerIdSupplier.getCallerCredentialsID() );
    }

    private CallerIdSupplierByType checkRequestInfoPaths( CallerIdSupplierByTypeFactory factory ) {
        CallerIdSupplierByType callerIdSupplier = factory.from( null );
        assertSame( CallerIdSupplierByTypeFactory.NULL_REQUEST_INFO, callerIdSupplier );
        assertNull( callerIdSupplier.getCallerCredentialsID() );
        assertNull( callerIdSupplier.getCallerRemoteAddressID() );

        callerIdSupplier = factory.from( mockRequestInfo );
        when( mockRequestInfo.getAuthorizationHeader() ).thenReturn( "Bearer " + FAKE_JWT );
        when( mockRequestInfo.getClientIP() ).thenReturn( FAKE_CLIENT_IP );

        assertEquals( FAKE_CLIENT_IP, callerIdSupplier.getCallerRemoteAddressID() );

        return callerIdSupplier;
    }
}