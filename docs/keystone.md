
Installing Keystone
==================================

    sudo apt-get install keystone python-keystone python-keystoneclient

The above will only install a v2 capable server as of May 6th, 2014.
To build a server from source, follow [these steps](keystone-setup-steps.txt)
Default password is ADMIN as defined in /etc/keystone/keystone.conf:admin_token


Creating a test user (no tenant/domain)
==================================


    export SERVICE_ENDPOINT=http://localhost:35357/v2.0
    export SERVICE_TOKEN=ADMIN
    keystone user-create --name=marissa2 --pass=koala2 --email=marissa2@test.org

    keystone service-create --name=keystoneV3 --type=identity --description="Keystone Identity Service V3"
    keystone endpoint-create  --service_id=<take ID output from above> --publicurl=http://localhost:5000/v3 --internalurl=http://localhost:5000/v3 --adminurl=http://localhost:35357/v3
    
Getting an user token, version 2,  (simple authentication)
==================================


    curl -v -d '{"auth":{"tenantName": "", "passwordCredentials": {"username": "marissa", "password": "koala"}}}' -H "Content-type: application/json" http://localhost:35357/v2.0/tokens    

Results in 


    {
        "access": {
            "token": {
                "expires": "2014-04-30T20:46:35Z", 
                "id": "f91a06a6d46b4f769dd2ca7992ed4c44"
            }, 
            "serviceCatalog": {}, 
            "user": {
                "username": "marissa", 
                "roles_links": [], 
                "id": "2e352099ab7a41b6beeb10d02f9cb082", 
                "roles": [], 
                "name": "marissa"
            }
        }
    }

Getting an user token, version 3,  (simple authentication)
==================================


    curl -X POST -H "Content-Type: application/json" -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"domain":{"name":"Default"},"name":"marissa2","password":"koala2"}}}}}' -D - http://localhost:5000/v3/auth/tokens

Results in


    {
        "token": {
            "issued_at": "2014-05-06T21:28:06.753348Z",
            "extras": {},
            "methods": ["password"],
            "expires_at": "2014-05-06T22:28:06.753321Z",
            "user": {
                "domain": {
                    "id": "default",
                    "name": "Default"
                },
                "id": "7d1a547acbb24516a357e51dc91c7948",
                "name": "marissa2"
            }
        }
    }

