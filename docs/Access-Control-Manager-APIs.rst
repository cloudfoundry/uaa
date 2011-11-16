==================================
Access Control Manager(ACM) APIs
==================================

.. contents:: Table of Contents

Overview
=========

This document describes the https/json APIs for the Access Control Manager of Cloud Foundry. 

For an overview of how the Access Control component will 
interact with other components in the Cloud Foundry system see 
`Interactions Between UAA, CC, CS and VMC <UAA-CC-CS-Interactions>`__.

The ACM is a service which governs user access to an object identified by a GUID. The ACM allows
definition of object types along with a permission set for the type. Access to the object 
can be controlled by defining an Access Control Entity (ace) on the object for the user. 
The ACM has API to support subsequent authorization decisions. A request can be made to the ACM
to check whether a user has a permission on an object.
In the case of the cloud controller, an app space is an ACM object. An object type for the app space 
is defined to set the list of allowed permissions for the app space. The ACM enables users to be 
assigned permissions for the app space and makes authorization decisions for the cloud controller 
by looking up the Access Control List (acl) of the app space object.
The design is intended to be as general as possible so that it can be used by other cloudfoundry 
components as well.


ACM Entities
============

**Object**
An object is an entity to which permissions are tied to and upon which access decisions are made. 
Objects typically contain an id, a name, type and a set of acls that determine permissions for a user.

acls

The object acl is of the form

"permission": ["user/group id 1", "user/group id 2", "user/group id 3"]

The permissions are determined by the object type.

owner permission - The "owner" permission on an object gives it's users/groups the ability to modify
any part of the object including deleting the object itself.

.. grant permission - The "grant" permission on an object gives it's users/groups ability to assign the
.. same or lower rights to another user/group on that object

**Object Type**
An object type is an entity that defines a set of applicable permissions for an object.

owner and grant are permissions that are assigned to an object type by default.

**User Group**
A user group is an entity that contains a group of users.


API Overview
============

The ACM will have API to support the following high level operations.

- CRUD operations for object types
- CRUD operations for objects
- CRUD operations for user groups
- Authorization decision operation on an object for a user/group and a permission

Let's take the cloud controller enabling collab spaces as an example of an ACM client.
 
Prior to using the ACM API for the first time, the cloud controller will make calls to the ACM to 
provision object types along with a permission set. For example, an object type 
"AppSpace" can be provisioned with the permission set ["create_app", "create_service", "delete_app", 
"delete_service", "view_app_logs", "restart_app"].

The cloud controller will create a container for apps known as the app space within it's own database.

As part of the process of creating an AppSpace, it will call the ACM to create an object with 
type "AppSpace" and assign a user/group with a subset of the supported permissions for that object 
type. The ACM will return a GUID for the object that will be stored by the cloud controller to be 
used for subsequent operations.

At the access decision point for the AppSpace, the cloud controller will call the ACM and pass
the GUID of the AppSpace, the user's id and the permission required. The ACM will return a true/false
decision.


Versioning of the API
------------------------------------------------------------------------

Versioning will be based on the Accept / Content-type headers for protocol versioning.
The request/response schema versioning element is already depicted in the schema. That will be used
to handle changes in the schema

.. note::TODO: Describe how version changes from release to release will handle backward compatibility of clients.


.. _`etag header`:


Object Versioning
------------------------------------------------------------------------

Each HTTP call to modify an object must include an ETag which identifies which version 
of the object is being modified. When using a PUT, the ETag read from a prior operation such as a GET 
must be passed unchanged. If the object has been modified since that GET, the operation will 
return a 409 error due to potentially conflicting changes.

See the the `etag section of HTTP 1.1 <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.19>`__ .

There is also a `section in the SCIM spec about etags <http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#etags>`__.


Authentication to the API
----------------------------------------

The ACM service will be authenticated to using HTTP basic authentication.

Additionally, the ACM will perform limited authorization based on the user id from the UAA.
For certain requests (details below), the client will need to send the user's id in an HTTP header
X-ACM-On-Behalf-Of to the ACM. The ACM will use this id to perform further authorization checks.

.. _onBehalfHeaderInfo:

**X-ACM-On-Behalf-Of header**

Send the user's id from the ACM in this HTTP header e.g.

::

   PUT /objects/id=54947df8-0e9e-4471-a2f9-9af509fb5889
   Host: internal.vcap.acm.com
   Accept: application/json
   Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
   ETag: "a330bc54f0671c9"
   X-HTTP-Method-Override: PATCH
   X-ACM-On-Behalf-Of: 5592254


HTTP Status Codes
-------------------

The following table describes the HTTP status codes and what they mean in the context of the 
ACM API

=========================== ======================= ===================================
Code                        Method                  Explanation
=========================== ======================= ===================================
200 OK                      GET                     No error.
201 CREATED                 POST                    Creation of an object was successful.
304 NOT MODIFIED            GET                     The object hasn't changed since the time specified in the request's If-Modified-Since header.
400 BAD REQUEST             *any*                   Invalid request URI or header, or unsupported nonstandard parameter.
401 UNAUTHORIZED            *any*                   Authorization required.
403 FORBIDDEN               *any*                   Unsupported standard parameter, or authentication or authorization failed.
404 NOT FOUND               GET, PUT, DELETE        Object not found.
409 CONFLICT                PUT, DELETE             Specified version number doesn't match object's latest version number.
500 INTERNAL SERVER ERROR   *any*                   Internal error. This is the default code that is used for all unrecognized server errors.
=========================== ======================= ===================================


Error Response Payloads
------------------------

======================= ==============  ===================================
Property                Type            Description
======================= ==============  ===================================
code                    number          error code
description             string          description of the error
uri                     string          Location where further information on this error code can be obtained
meta                    object          Meta information about this entity
======================= ==============  ===================================

An example of an error payload is as follows::

    {
       "code":100,
       "description":"An unknown internal error occurred",
       "meta":{
          "object_id":"e0c46e6b-a89d-46cc-abd3-46553ffb14dc",
          "schema":"urn:acm:schemas:1.0"
       }
    }


Error code ranges

.. note:: TODO - For now, error codes between 1000-2000 will be returned

HTTPS/JSON APIs
=====================================

Operations on objects
------------------------------------------------------------------


Create Object: POST /objects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Creates ACM objects

===============  ===================================
HTTP Method      POST
URI              /objects
Request Format   Refer to the `Object Schema`_
Response Format  Refer to the `Object Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================

The service responds with an instance of the object schema.

The operation requires passing the user id in the header. See `X-ACM-On-Behalf-Of header`__ 

__ onBehalfHeaderInfo_

Update Object: PUT /objects/#{object_id}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Complete update to an ACM object**

===============  ===================================
HTTP Method      PUT
URI              /objects/#{object_id}
Request Format   Refer to the `Object Schema`_
Response Format  Refer to the `Object Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================

The service responds with an instance of the object schema.

The operation requires passing the user id in the header. See `X-ACM-On-Behalf-Of header`__ 

__ onBehalfHeaderInfo_



**Partial updates to an ACM object**

Sometimes, instead of updating the entire object, it may be necessary to update only a small
section of the schema. e.g. Add a user to a permissionSet.

A partial update allows the caller to only specify the addition/update that's required to the 
schema. The API requires an additional header in the request to indicate that this is for a partial
update.

=================  ===================================
HTTP Method        PUT
URI                /objects/#{object_id}
Additional header  X-HTTP-Method-Override PATCH
Request Format     Refer to the `Object Schema`_
Response Format    Refer to the `Object Schema`_ 
Response Codes     | 200 - Operation was successful
                   | 400 - Malformed request format
                   | 401 - Not Authorized
=================  ===================================

The service responds with an instance of the object schema.

.. _`partial update`:

Partial Update to an object: PUT /objects/#{object_id}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Since the content of some objects can get large or complex, e.g. Group or Project, a PATCH operation allows for a partial update.

There are three types of attributes that will be affected differently depending on their type

* Singular attributes:
  Singular attributes in the PATCH request body replace the attribute on the Object.
  
* Complex attributes:
  Complex Sub-Attribute values in the PATCH request body are merged into the complex attribute on the Object.
  
* Plural attributes:
  Plural attributes in the PATCH request body are added to the plural attribute on the Object if 
  the value does not yet exist or are merged into the matching plural value on the Object if the 
  value already exists. Plural attribute values are matched by comparing the value Sub-Attribute 
  from the PATCH request body to the value Sub-Attribute of the Object. Plural attributes that do 
  not have a value Sub-Attribute (for example, users) cannot be matched for the purposes of 
  partially updating an an existing value. These must be deleted then added. Similarly, plural 
  attributes that do not have unique value Sub-Attributes must be deleted then added.

For some examples see `Partial Updates to an object`_.



Get Object: GET /objects/#{object_id}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Gets ACM objects

===============  ===================================
HTTP Method      GET
URI              /objects/#{object_id}
Request Format   N/A
Response Format  Refer to the `Object Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================

The service responds with the json for the entire object.


Delete Object: DELETE /objects/#{object_id}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Deletes an ACM object

===============  ===================================
HTTP Method      DELETE
URI              /objects/#{object_id}
Request Format   N/A
Response Format  N/A
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
===============  ===================================

The operation requires passing the user id in the header. See `X-ACM-On-Behalf-Of header`__ 

__ onBehalfHeaderInfo_


Operations on groups
------------------------------------------------------------------


Create Group: POST /groups
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Creates ACM group

===============  ===================================
HTTP Method      POST
URI              /groups
Request Format   Refer to the `User Group Schema`_
Response Format  Refer to the `User Group Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================

The operation requires passing the user id in the header. See `X-ACM-On-Behalf-Of header`__ 

__ onBehalfHeaderInfo_

Update Group: PUT /groups/#{group_id}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Updates an ACM group

===============  ===================================
HTTP Method      PUT
URI              /groups/#{group_id}
Request Format   Refer to the `User Group Schema`_
Response Format  Refer to the `User Group Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================

The operation requires passing the user id in the header. See `X-ACM-On-Behalf-Of header`__ 

__ onBehalfHeaderInfo_

Get Group: GET /groups/#{group_id}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Gets an ACM group

===============  ===================================
HTTP Method      GET
URI              /groups/#{group_id}
Request Format   N/A
Response Format  Refer to the `User Group Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================


Delete Group: DELETE /groups/#{group_id}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Deletes an ACM group

===============  ===================================
HTTP Method      DELETE
URI              /groups/#{group_id}
Request Format   N/A
Response Format  N/A
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
===============  ===================================

The operation requires passing the user id in the header. See `X-ACM-On-Behalf-Of header`__ 

__ onBehalfHeaderInfo_

Operations on object types
------------------------------------------------------------------


Create Object type: POST /object_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Creates ACM object type

===============  ===================================
HTTP Method      POST
URI              /object_types
Request Format   Refer to the `Object Type Schema`_
Response Format  Refer to the `Object Type Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================


Update Object Type: PUT /object_types/#{object_type_id}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Updates an ACM Object Type

===============  ===================================
HTTP Method      PUT
URI              /object_types/#{object_type_id}
Request Format   Refer to the `Object Type Schema`_
Response Format  Refer to the `Object Type Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================


Get Object Type: GET /object_types/#{object_type_id}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Gets an ACM Object Type

===============  ===================================
HTTP Method      GET
URI              /object_types/#{object_type_id}
Request Format   Refer to the `Object Type Schema`_
Response Format  Refer to the `Object Type Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================



Delete Object Type: DELETE /object_types/#{object_type_id}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Deletes an ACM Object Type

===============  ===================================
HTTP Method      GET
URI              /object_types/#{object_type_id}
Request Format   N/A
Response Format  N/A
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
===============  ===================================

**An Object Type will not be able to be deleted until all objects using that object type 
are deleted.**


Partial Updates to an Object
---------------------------------------

**Delete a user 3749285 from the permissionSet of the object**

::

    GET /objects/54947df8-0e9e-4471-a2f9-9af509fb5889
    Host: internal.vcap.acm.com
    Accept: application/json
    Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==


    HTTP/1.1 200 OK
    Content-Type: application/json
    Location: http://internal.vcap.acm.com/objects/54947df8-0e9e-4471-a2f9-9af509fb5889
    ETag: "f250dd84f0671c3"
    
    {
       "name":"www_staging",
       "type":"app_space",
       "id":"54947df8-0e9e-4471-a2f9-9af509fb5889",
       "additionalInfo":{
          "org":"vmware"
       },
       "acl":{
          "read_app":[
             "3749285",
             "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
          ],
          "update_app":[
             "3749285",
             "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
          ],
          "read_app_logs":[
             "3749285",
             "4a9a8c60-0cb2-11e1-be50-0800200c9a66",
             "d1682c64-040f-4511-85a9-62fcff3cbbe2"
          ],
          "read_service":[
             "3749285",
             "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
          ],
          "write_service":[
             "3749285",
             "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
          ]
       },
       "meta":{
          "updated":1273740902,
          "created":1273726800,
          "schema":"urn:acm:schemas:1.0"
       }
    }


::

   PUT /objects/54947df8-0e9e-4471-a2f9-9af509fb5889
   Host: internal.vcap.acm.com
   Accept: application/json
   Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
   ETag: "a330bc54f0671c9"
   X-HTTP-Method-Override: PATCH

   {
     "acl":{
        "read_app":[
          "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
        ],
        "update_app":[
          "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
        ],
        "read_app_logs":[
          "4a9a8c60-0cb2-11e1-be50-0800200c9a66",
          "d1682c64-040f-4511-85a9-62fcff3cbbe2"
        ],
        "read_service":[
          "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
        ],
        "write_service":[
          "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
        ]
     }
   }
   
   
   HTTP/1.1 200 OK
   Content-Type: application/json
   Location: http://internal.vcap.acm.com/objects/54947df8-0e9e-4471-a2f9-9af509fb5889
   ETag: "f250dd84f0671c3"
   
   {
      "name":"www_staging",
      "type":"app_space",
      "id":"54947df8-0e9e-4471-a2f9-9af509fb5889",
      "additionalInfo":{
          "org":"vmware"
      },
      "acl":{
          "read_app":[
             "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
          ],
          "update_app":[
             "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
          ],
          "read_app_logs":[
             "4a9a8c60-0cb2-11e1-be50-0800200c9a66",
             "d1682c64-040f-4511-85a9-62fcff3cbbe2"
          ],
          "read_service":[
             "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
          ],
          "write_service":[
             "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
          ]
       },
       "meta":{
          "updated":1273740902,
          "created":1273726800,
          "schema":"urn:acm:schemas:1.0"
      }
    }


**Delete the update_app permission from the app space**

::

   PUT /objects/id=54947df8-0e9e-4471-a2f9-9af509fb5889
   Host: internal.vcap.acm.com
   Accept: application/json
   Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
   ETag: "a330bc54f0671c9"
   X-HTTP-Method-Override: PATCH

   {
       "permissionSet":{
          "update_app":null
       }
   }
   
   
   HTTP/1.1 200 OK
   Content-Type: application/json
   Location: http://internal.vcap.acm.com/objects/54947df8-0e9e-4471-a2f9-9af509fb5889
   ETag: "f250dd84f0671c3"
   
   {
     "name":"www_staging",
     "type":"app_space",
     "id":"54947df8-0e9e-4471-a2f9-9af509fb5889",
     "additionalInfo":{
        "org":"vmware"
     },
     "acl":{
        "read_app":[
          "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
        ],
        "read_app_logs":[
          "4a9a8c60-0cb2-11e1-be50-0800200c9a66",
          "d1682c64-040f-4511-85a9-62fcff3cbbe2"
        ],
        "read_service":[
          "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
        ],
        "write_service":[
          "4a9a8c60-0cb2-11e1-be50-0800200c9a66"
        ]
      },
      "meta":{
        "updated":1273740902,
        "created":1273726800,
        "schema":"urn:acm:schemas:1.0"
     }
   }


Access control and permission checks
---------------------------------------

Check Access: GET /objects/#{object_id}/access?id=#{subject_id}&p=#{permission1}&p=#{permission2}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Checks Access of a subject (user/group) to an ACM object

===============  ===================================
HTTP Method      GET
URI              /objects/#{object_id}/access?id=#{subject_id}&p=#{permission1}&p=#{permission2}
Request Format   N/A
Response Format  See below
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
===============  ===================================

The method will return the following response if the subject (user/group) has all the requested 
permissions::

    {"response":"true"}

If the subject does not have a permission in the requested list, the API will return the following::

    {"response":"false"}


Batch Check Access: POST /objects/access
####################################################################################################

Checks Access of a group of subjects (user/group) and ACM objects

===============  ===================================
HTTP Method      POST
URI              /objects/access
Request Format   See below
Response Format  See below
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
===============  ===================================

Request format:: 

    [
        {
            "id": #{object_id1},
            "p": [#{permission1}, #{permission2}, ...]
        },
        {
            "id": #{object_id2},
            "p": [#{permission1}, #{permission2}, ...]
        }
    ]

Response format::

    [
        {
            "id": #{object_id1},
            "response": "false"
        },
        {
            "id": #{object_id2},
            "response": "true"
        }
    ]


Check Permissions: GET /objects/#{object_id}/permissions?id=#{subject_id}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Gets the permission set for the subject (user/group) on an object

===============  ===================================
HTTP Method      GET
URI              /objects/#{object_id}/permissions?id=#{subject_id}
Request Format   N/A
Response Format  N/A
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
===============  ===================================

The method will return the following response if the subject (user/group) has some permissions on the
object::

    {
        "permissionSet": ["read_app", "update_app"]
    }

If the subject does not have a permission, the API will return the following::

    {
        "permissionSet":null
    }
    

Batch Check Permissions: POST /objects/permissions
####################################################################################################

Gets the permission set for a set of subjects (user/group) on a set of objects

===============  ===================================
HTTP Method      POST
URI              /objects/permissions
Request Format   See below
Response Format  See below
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
===============  ===================================

Request format:: 

    [
        {
            "id": #{object_id1},
            "subject": #{subject_id1}
        },
        {
            "id": #{object_id2},
            "subject": #{subject_id2}
        }
    ]

Response format::

    [
        {
            "id": #{object_id1},
            "permissionSet": ["read_app", "update_app"]
        },
        {
            "id": #{object_id2},
            "permissionSet": null
        }
    ]


ACM Schemas
=================

Object Type Schema
----------------------

Attributes

======================= ============== ===================================
Property                Type           Description
======================= ============== ===================================
name                    string         name of this object type. Must be unique across the ACM.
id                      string         immutable identifier (not to be included in a request). 
additionalInfo          string         optional - additional information this object.
permissionSet           Array[String]  Set of object permissions for this type.
meta                    object         Meta information about this entity.
======================= ============== ===================================

Example::

    {
       "object_type":"app_space",
       "id":"54947df8-0e9e-4471-a2f9-9af509fb5889",
       "additionalInfo":{"component":"cloud_controller"},
       "permissionSet": [
             "read_app",
             "update_app",
             "read_app_logs",
            "read_service",
             "write_service"
       ],
       "meta":{
          "updated":1273740902,
          "created":1273726800,
          "schema":"urn:acm:schemas:1.0"
       }
    }
    

Object Schema
----------------------

Attributes

======================= ==============  ===================================
Property                Type            Description
======================= ==============  ===================================
name                    string          name of this object.
type                    string          type of this object.
id                      string          immutable identifier (not to be included in a request). 
                                        It is returned in the response.
additionalInfo          string          optional - additional information this object.
acl                     object          map of object permissions => set of users.
meta                    object          meta information about this entity.
======================= ==============  ===================================

Example::

    {
       "name":"www_staging",
       "type":"app_space",
       "id":"54947df8-0e9e-4471-a2f9-9af509fb5889",
       "additionalInfo":{"org":"vmware"},
       "acl": {
             "read_app": ["3749285", "4a9a8c60-0cb2-11e1-be50-0800200c9a66"],
             "update_app": ["3749285", "4a9a8c60-0cb2-11e1-be50-0800200c9a66"],
             "read_app_logs": ["3749285", "4a9a8c60-0cb2-11e1-be50-0800200c9a66", "d1682c64-040f-4511-85a9-62fcff3cbbe2"],
            "read_service": ["3749285", "4a9a8c60-0cb2-11e1-be50-0800200c9a66"],
             "write_service": ["3749285", "4a9a8c60-0cb2-11e1-be50-0800200c9a66"]
       },
       "meta":{
          "updated":1273740902,
          "created":1273726800,
          "schema":"urn:acm:schemas:1.0"
       }
    }


User Group Schema
----------------------

Attributes

======================= ==============  ===================================
Property                Type            Description
======================= ==============  ===================================
name                    string          name of this user group
id                      string          immutable identifier (not to be included in a request). 
                                        It is returned in the response.
additionalInfo          string          additional information for this user group
users                   Array[string]   set of user ids of members of this group
admins                  Array[string]   set of user ids of admins of this group
meta                    object          meta information about this entity
======================= ==============  ===================================

Example::

    {
       "name":"www-developers",
       "id":"54947df8-0e9e-4471-a2f9-9af509fb5889",
       "additionalInfo":{"org":"vmware"},
       "users": [123268, 245424, 335111, 930290, 123055],
       "admins": [123268, 111332],
       "meta":{
          "updated":1273740902,
          "created":1273726800,
          "schema":"urn:acm:schemas:1.0"
       }
    }


Open Issues
=============

- Deleting object types needs to be figured out.

- Return codes need to be looked at again. Need to update return codes for operation failures.
