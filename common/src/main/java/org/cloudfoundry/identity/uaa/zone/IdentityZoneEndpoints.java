package org.cloudfoundry.identity.uaa.zone;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/identity_zones")
public class IdentityZoneEndpoints {

    private IdentityZoneProvisioning dao;

    @RequestMapping(method = RequestMethod.POST)
    public IdentityZone createIdentityZone(@RequestBody IdentityZone zone) {
        return dao.createZone(zone);
    }

    public void setIdentityZoneProvisioning(IdentityZoneProvisioning dao) {
        this.dao = dao;
    }
}
