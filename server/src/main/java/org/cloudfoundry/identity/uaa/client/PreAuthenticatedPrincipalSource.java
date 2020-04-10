package org.cloudfoundry.identity.uaa.client;

/** @author Dave Syer */
public interface PreAuthenticatedPrincipalSource<T> {

  T getPrincipal();
}
