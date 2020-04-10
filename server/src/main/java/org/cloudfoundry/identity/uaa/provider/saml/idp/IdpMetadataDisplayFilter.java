package org.cloudfoundry.identity.uaa.provider.saml.idp;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;

public class IdpMetadataDisplayFilter extends MetadataDisplayFilter {

  @Override
  protected void processMetadataDisplay(HttpServletRequest request, HttpServletResponse response)
      throws IOException, ServletException {
    super.processMetadataDisplay(request, response);
    response.setHeader(
        "Content-Disposition",
        String.format(
            "attachment; filename=\"saml-%sidp.xml\"",
            !IdentityZoneHolder.isUaa() ? IdentityZoneHolder.get().getSubdomain() + "-" : ""));
  }
}
