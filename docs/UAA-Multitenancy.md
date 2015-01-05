# UAA Multitenancy

## Identity Zones

An Identity Zone represents the boundary behind which OAuth Clients, Users, and Identity Providers can interact. 

### Identiy Zone API

#### PUT /identity-zones/{id}
* Requires scope `zones.create`
* Creates / updates an identity zone with the given {id}
* Sample request

```
curl -v -X PUT -H 'Authorization: Bearer [ACCESS_TOKEN]' \
-H 'Content-Type: application/json' \
-d'{"subdomain":"zone1","name":"Zone 1","description":"test zone"}'
```
* Returns 201 for a newly created Identity Zone, 200 for an updated Identity Zone, or 409 if the subdomain already exists.