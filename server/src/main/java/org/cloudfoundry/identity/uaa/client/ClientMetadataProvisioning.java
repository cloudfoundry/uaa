
package org.cloudfoundry.identity.uaa.client;

import java.util.List;

public interface ClientMetadataProvisioning {

    List<ClientMetadata> retrieveAll(String zoneId);

    ClientMetadata retrieve(String id, String zoneId);

    ClientMetadata update(ClientMetadata resource, String zoneId);

}
