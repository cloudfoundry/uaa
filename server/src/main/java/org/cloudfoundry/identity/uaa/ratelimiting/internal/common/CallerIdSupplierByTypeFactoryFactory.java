package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import lombok.RequiredArgsConstructor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.AuthorizationCredentialIdExtractor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CallerIdSupplierByType;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CallerIdSupplierByTypeFactory;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;

import static org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils.SupplierWithCaching;
import static org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils.normalizeToNull;

public class CallerIdSupplierByTypeFactoryFactory {
    public static CallerIdSupplierByTypeFactory from( AuthorizationCredentialIdExtractor credentialIdExtractor ) {
        return (credentialIdExtractor == null) ?
               new FactoryNoCredentialIdExtractor() :
               new FactoryWithCredentialIdExtractor( credentialIdExtractor );
    }

    private static class FactoryNoCredentialIdExtractor implements CallerIdSupplierByTypeFactory {
        @Override
        public CallerIdSupplierByType from( RequestInfo request ) {
            return (request == null) ? NULL_REQUEST_INFO : new NoCredentialIdExtractor( request );
        }
    }

    // public for testing
    @RequiredArgsConstructor
    public static class FactoryWithCredentialIdExtractor implements CallerIdSupplierByTypeFactory {
        // public for testing
        public final AuthorizationCredentialIdExtractor credentialIdExtractor;

        @Override
        public CallerIdSupplierByType from( RequestInfo request ) {
            return (request == null) ? NULL_REQUEST_INFO : new WithCredentialIdExtractor( request, credentialIdExtractor );
        }

        @Override
        public String getCallerCredentialsIdSupplierDescription() {
            return credentialIdExtractor.getDescription();
        }
    }

    protected static class NoCredentialIdExtractor extends CallerIdSupplierByTypeFactory.NoCallerDetails implements CallerIdSupplierByType {
        private final SupplierWithCaching supplier;

        protected NoCredentialIdExtractor( RequestInfo info ) {
            supplier = new SupplierWithCaching(
                    () -> normalizeToNull( info.getClientIP() ) );
        }

        @Override
        public String getCallerRemoteAddressID() {
            return supplier.get();
        }
    }

    private static class WithCredentialIdExtractor extends NoCredentialIdExtractor {
        private final SupplierWithCaching supplier;

        public WithCredentialIdExtractor( RequestInfo info, AuthorizationCredentialIdExtractor credentialIdExtractor ) {
            super( info );
            supplier = new SupplierWithCaching(
                    () -> normalizeToNull( credentialIdExtractor.mapAuthorizationToCredentialsID( info ) ) );
        }

        @Override
        public String getCallerCredentialsID() {
            return supplier.get();
        }
    }
}
