package org.cloudfoundry.identity.uaa.provider.saml;

import java.io.File;
import java.util.Timer;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;

public class FilesystemMetadataProvider
    extends org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider {

  public FilesystemMetadataProvider(Timer backgroundTaskTimer, File metadata)
      throws MetadataProviderException {
    super(backgroundTaskTimer, metadata);
  }

  @Override
  public byte[] fetchMetadata() throws MetadataProviderException {
    return super.fetchMetadata();
  }
}
