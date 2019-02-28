package org.cloudfoundry.identity.uaa;

import org.springframework.context.annotation.ImportResource;

@ImportResource(locations = {"classpath:fake-password-encoder.xml"})
public class FakePasswordEncoderConfig {
}
