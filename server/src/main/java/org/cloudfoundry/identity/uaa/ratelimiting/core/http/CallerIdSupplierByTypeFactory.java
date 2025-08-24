package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

public interface CallerIdSupplierByTypeFactory {
    CallerIdSupplierByType from(RequestInfo request);

    default String getCallerCredentialsIdSupplierDescription() {
        return "None";
    }

    class NoCallerDetails implements CallerIdSupplierByType {
        @Override
        public String getCallerCredentialsID() {
            return null;
        }

        @Override
        public String getCallerRemoteAddressID() {
            return null;
        }
    }

    CallerIdSupplierByType NULL_REQUEST_INFO = new NoCallerDetails();
}
