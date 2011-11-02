===========================
Collaboration Spaces APIs
===========================

.. contents:: Table of Contents

.. .. sectnum::

Overview
=========

This document describes the https/json APIs for the collaboration spaces component of Cloud Foundry. 

For an overview of how the collaboration spaces component will interact with other components in the Cloud Foundry system see `Interactions Between UAA, CC, CS and VMC <UAA-CC-CS-Interactions>`__.

There is also a `vision document for collaboration spaces`__.

__ https://wiki.springsource.com/display/ACDEV/Collaboration+Spaces+Model

* A service which needs to control user access to a set of resources (e.g. the cloud controller or the BOSH director) can use Collab Spaces to make authorization decisions. The resource server can send a user authentication token, an authorization context, and a series of required resource-permission pairs to Collab Spaces and get an authorization decision in return.
  - In the case of the cloud controller, the resources are apps and services. However, the design is intended to be as general as possible so that it can be used by other cloudfoundry components as well, such as the BOSH director.
* Collab Spaces knows how to handle user authentication tokens and it owns the concepts of orgs, projects with role-maps/ACLs, and groups. The resource server does not need to know or manage anything about these things. 
* Collab Spaces handles authorization of authenticated users relative to their selected context for access to resources. 
* Collab Spaces has the following configuration options

  - Database configuration
	
General API Operation
======================

Evolutionary Approach
----------------------

In order to evolve the collab spaces into the cloud controller code and get the feature out earlier, the collab spaces module will initially be a Ruby module included by the cloud controller. HTTP/JSON interfaces will also be implemented as part of the cloud controller as a first pass. In due course, the collab spaces will become a separate module accessible only the HTTP/JSON interfaces.

Initial Authorization System
-----------------------------

Minimal parts of some features will be implemented initially:

* Support only for a default project ('all' project).
* Single set of role maps per org

  - Each rolemap row contains a name, set of users, set of permissions/resource pairs.
  - e.g. Users, CRUD to apps, services, apps/*, services/*

* Essentially the 'all' project from the collab spaces design. 

Modeled after Simple Cloud Identity Management (SCIM) Proposed Standard
------------------------------------------------------------------------

The various elements of the collab spaces system are modeled as resources similar to the Users and Groups resources of the proposed `Simple Cloud Identity Management <http://www.simplecloud.info>`__ Standard. 

Links to specs, comment on etags, Patch. 

All specific resource replies and updates should return/accept and etag.


Versioning of the API
------------------------------------------------------------------------

Versioning will be based on the Accept / Content-type headers for protocol versioning.
The request/response schema versioning element is already depicted in the schema. That will be used
to handle changes in the schema

.. note::TODO: Describe how version changes from release to release will handle backward compatibility of clients.


.. _`etag header`:

Resource Versioning
------------------------------------------------------------------------

Each HTTP call to modify a collab spaces resource must include an ETag which identifies which version of the resource is being modified. When using a PUT, the ETag read from a prior operation such as a GET 
must be passed unchanged. If the resource has been modified since that GET, the operation will 
return a 409 error due to potentially conflicting changes.

See the the `etag section of HTTP 1.1 <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.19>`__ .

There is also a `section in the SCIM spec about etags <http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#etags>`__.


Authentication to the API
----------------------------------------

The collab spaces API will be authenticated to using an OAuth2 token in the HTTP header of the API
call. Here is an example::

  POST /acme/prod/apps HTTP/1.1
  Host: server.example.com
  Authorization: Bearer vF9dft4qmT
  Content-Type: application/json-encoded
  Accept: application/json
  
.. note:: TODO: this describes how the user's authorization token is sent to the collab spaces code, but the token really represents user access to a resource server, and the resource server is asking collab spaces to perform the authz calculations on its behalf. 

Specifying an Authorization Context
------------------------------------

Before using the Collab Spaces API, it's important to understand the authorization context.
All the URIs operate in a specific authorization context that consists of an org and a project.
The system is bootstrapped with the default org "all" and it's default project "all".

The section of the URI after the authorization context consists of the resource type and the 
resource name.

Therefore, a POST to the URI /all/all/org indicates that the user is operating in the (default)
authorization context of "all" orgs and "all" projects and intends to create a resource of type "org".

After the creation of an org "acme" with a post to /all/all/org, a new org "acme" is created with it's
default "all" project creating the authorization context /acme/all. Therefore a resource of type "app"
in the acme org can be retrieved using a GET call to /acme/all/app

e.g. /*org_name*/*proj_name*


HTTP Status Codes
-------------------

The following table describes the HTTP status codes and what they mean in the context of the 
Collab Spaces API

=========================== ======================= ===================================
Code                        Method                  Explanation
=========================== ======================= ===================================
200 OK                      GET                     No error.
201 CREATED                 POST                    Creation of a resource was successful.
304 NOT MODIFIED            GET                     The resource hasn't changed since the time specified in the request's If-Modified-Since header.
400 BAD REQUEST             *any*                   Invalid request URI or header, or unsupported nonstandard parameter.
401 UNAUTHORIZED            *any*                   Authorization required.
403 FORBIDDEN               *any*                   Unsupported standard parameter, or authentication or authorization failed.
404 NOT FOUND               GET, PATCH, PUT, DELETE Resource not found.
409 CONFLICT                PATCH, PUT, DELETE      Specified version number doesn't match resource's latest version number.
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
       "uri":"http://www.cloudfoundry.com/docs/collab_spaces_api_documentation#error_100",
       "meta":{
          "org":"VMware",
          "resource_id":"e0c46e6b-a89d-46cc-abd3-46553ffb14dc",
          "schema":"urn:collabspaces:schemas:1.0"
       }
    }


Error code ranges

.. note:: TODO - For now, error codes between 1000-2000 will be returned

HTTPS/JSON APIs
=============================

Create Resource: POST /*context*/*restype* ( *resdata* )
------------------------------------------------------------------

Can create resources internal to collab spaces like org, group, project as well as general external resources like app and service. 

===============  ===================================
HTTP Method      POST
URI              /*context*/*res_type*
Request Format   Refer to the `Resource Schemas`_
Response Format  Refer to the `Resource Schemas`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================

Delete Resource: DELETE /*context*/*restype*/*name* or *_id*
--------------------------------------------------------------------

Deleting an Org will cause all resources within that org to be deleted. Deleting a Project will delete the user assignments and permission sets to be deleted with the project itself, but other internal resources in the org are not affected.

Delete resource by name:

===============  ===================================
HTTP Method      DELETE
URI              /*context*/*res_type*/*res_name*
Request Format   *N/A*
Response Format  { "id":*"res_id"* }
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
                 | 404 - Not found
===============  ===================================

Delete resource by id:

===============  ===================================
HTTP Method      DELETE
URI              /*context*/*res_type*/*_res_id*
Request Format   *N/A*
Response Format  { "id":*"res_id"* }
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
                 | 404 - Not found
===============  ===================================

    
Full Update Resource: PUT /*context*/*restype*/*name* or *_id*
----------------------------------------------------------------

There are two ways to update a project. This can be done either using either the HTTP PUT or PATCH 
operation. The PUT operation performs a full update. It will be necessary to retrieve the entire 
Resource (or Project) and PUT the desired modifications as the operation overwrites all previously 
stored data. PUT operation returns a 200 OK response code and the entire Resource within the response body.

The PUT operation to update a resource is described below.

===============  ========================================
HTTP Method      PUT
URI              /*context*/*res_type*/*res_name*
Request Format   Refer to the `Resource Schemas`_ for *res_type*
Response Format  Refer to the `Resource Schemas`_ for *res_type*
Response Codes   | 200 - Operation was successful
                 | 400 — Malformed request format
                 | 401 - Not Authorized
                 | 404 - Not found
===============  ========================================

.. _`partial update`:

Partial Update Resource: PATCH /*context*/*restype*/*name* or *_id*
----------------------------------------------------------------------

Since the content of some resources can get large or complex, e.g. Group or Project, a PATCH operation allows for a partial update.

There are three types of attributes that will be affected differently depending on their type

* Singular attributes:
  Singular attributes in the PATCH request body replace the attribute on the Resource.
  
* Complex attributes:
  Complex Sub-Attribute values in the PATCH request body are merged into the complex attribute on the Resource.
  
* Plural attributes:
  Plural attributes in the PATCH request body are added to the plural attribute on the Resource if 
  the value does not yet exist or are merged into the matching plural value on the Resource if the 
  value already exists. Plural attribute values are matched by comparing the value Sub-Attribute 
  from the PATCH request body to the value Sub-Attribute of the Resource. Plural attributes that do 
  not have a value Sub-Attribute (for example, users) cannot be matched for the purposes of 
  partially updating an an existing value. These must be deleted then added. Similarly, plural 
  attributes that do not have unique value Sub-Attributes must be deleted then added.

For some examples see `Partial Updates to a Project`_.

Get Specific Resource: GET /*context*/*restype*/*name* or *_id*
----------------------------------------------------------------

Get information about a specific resource. Data will be returned in JSON according to the schema of the resource type.

All such resource representation will include an `etag header`_.

Query Resources: GET /*context*/*restype*? *query*
----------------------------------------------------------------

List/query resources: GET /*context*/*res_type*? query and filter

All such resource representation will include an `etag header`_.

Check Authorizations: POST /*context*/authorized (*(restype, resname, perms)[]*) 
--------------------------------------------------------------------------------------------

The following API call may be made to get an authorization decision for one or more resources. The user will 
need to be authenticated to the API, see `Authentication to the API`_.

===============  ===================================
HTTP Method      POST
URI              /*org_name*/*proj_name*/authorized
Request Format   ::

                    [
                        {
                    	    "name": "res_name_1",
                            "type": "res_type_1",
                            "permissionSet": ["perm", ...]
                        },
                        {
                    	    "name": "res_name_2",
                            "type": "res_type_2",
                            "permissionSet": ["perm", ...]
                        }
                        ...
                    ]

Response Format  *Empty*
Response Codes   | 200 - Operation was successful (Authorized)
                 | 400 - Malformed request format
                 | 401 - Not Authorized
                 | 404 - Resource does not exist
===============  ===================================

Resource Schemas
=================

Org Schema
-----------

Attributes

======================= ==============  ===================================
Property                Type            Description
======================= ==============  ===================================
name                    string          name of this organization
id                      string          immutable identifier
description             string          optional description
authenticationEndpoint  string          URL to the UAA for this org
meta                    object          Meta information about this entity
======================= ==============  ===================================

Example::

    {
       "name":"VMware Inc.",
       "id":"54947df8-0e9e-4471-a2f9-9af509fb5889",
       "description":"VMware Inc.",
       "authenticationEndpoint": "https://uaa.cloudfoundry.com",
       "meta":{
          "updated":1273740902,
          "created":1273726800,
          "schema":"urn:collabspaces:schemas:1.0"
       }
    }


Project Schema
---------------

Attributes

======================= ==============  ===================================
Property                Type            Description
======================= ==============  ===================================
name                    string          name of this project
id                      string          immutable identifier
description             string          optional description
roles                   Array[Object]   Roles for this project described in next table
resourceList            Array[String]   List of resources in scope for the roles and permissions of this project
meta                    object          Meta information about this entity
======================= ==============  ===================================

Role attributes

======================= ==============  ===================================
Property                Type            Description
======================= ==============  ===================================
name                    string          name of this role
users                   Array[String]   List of individual users in this role
groups                  Array[String]   List of groups in this role
acls                    Array[Object]   List of resource - permission set pairs 
meta                    object          Meta information about this entity
======================= ==============  ===================================

Example::

    {
       "name":"www",
       "id":"69165e21-8169-4d32-b325-a109a3e31f27",
       "description":"project for the www app for cloud foundry",
       "roles":{
          "admin":{
             "users":[ "jdsa@vmware.com", "olds@vmware.com" ],
             "acls":[
                {
                   "name":"*",
                   "type":"*",
                   "permissionSet":[ "CREATE", "READ", "UPDATE", "DELETE" ]
                }
             ]
          },
          "developers":{
             "users":[ "jdsa@vmware.com", "andrewss@vmware.com" ],
             "acls":[
                {
                   "name":"*",
                   "type":"app",
                   "permissionSet":[ "CREATE", "READ", "UPDATE", "DELETE" ]
                },
                {
                   "name":"www",
                   "type":"app",
                   "permissionSet":[ "READ" ]
                }
             ]
          },
          "monitors":{
             "users":[ "sam@vmware.com", "sue@vmware.com" ],
             "acls":[
                {
                   "name":"*",
                   "type":"*",
                   "permissionSet":[ "READ" ]
                }
             ]
          }
       },
       "resourceList":[
          "www:type=app",
          "wwwOld:type=app",
          "mysql:type=service"
       ],
       "meta":{
          "updated":1273740902,
          "created":1273726800,
          "schema":"urn:collabspaces:schemas:1.0"
       }
    }

Group Schema
-------------

.. note:: see SCIM

======================= ==============  ===================================
Property                Type            Description
======================= ==============  ===================================
name                    string          name of this role
users                   Array[String]   List of individual users in this role
meta                    object          Meta information about this entity
======================= ==============  ===================================

General Resource Schema
--------------------------

======================= ==============  ===================================
Property                Type            Description
======================= ==============  ===================================
name                    string          name of this resource
type                    string          type of this resource
id                      string          immutable identifier assigned by collab spaces
description             string          optional description
meta                    object          Meta information about this entity
======================= ==============  ===================================

Example::

    {
       "name":"www",
       "type":"app",
       "id":"76ca5cc0-ce6e-4eec-bab2-ae523091adf3",
       "description":"www app for cloudfoundry",
       "resource-metadata":{
          "metadata-key":"metadata-value"
       },
       "meta":{
          "updated":1273740902,
          "created":1273726800,
          "schema":"urn:collabspaces:schemas:1.0"
       }
    }

Example API and Schema Usage
==============================

.. note:: TODO: need other examples for

* Update name or UAA-URL in an org
* Replace Role in a project
* Add/remove resource to resource list in project
* Add/remove user from a group

.. note:: TODO: Might be good to show request and responses inline for these examples.

Create an Org
--------------

===============  ===================================
HTTP Method      POST
URI              /all/all/org
Request Format   Refer to the `Org Schema`_
Response Format  Refer to the `Org Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================

Get Information for Specific Org
-----------------------------------

You can search Org information by name:

===============  ===================================
HTTP Method      GET
URI              /all/all/org/*org_name*
Request Format   *N/A*
Response Format  Refer to the `Org Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 404 - Not found
===============  ===================================
	
Or by id:
	
===============  ===================================
HTTP Method      GET
URI              /all/all/org/*_org_id*
Request Format   *N/A*
Response Format  Refer to the `Org Schema`_
Response Codes   | 200 - Operation was successful
                 | 404 - Not found
===============  ===================================
	
Delete an Org
--------------

===============  ===================================
HTTP Method      DELETE
URI              /all/all/org/*org_name*
Request Format   *N/A*
Response Format  Refer to the `Org Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
                 | 404 - Not found
===============  ===================================

Create Projects in an Org
--------------------------

Projects are a type of resource. Although the interface to manipulate projects is the same as other resources, the internal
representation may differ.

===============  ===================================
HTTP Method      POST
URI              /*org_name*/all/project
Request Format   Refer to the `Project Schema`_ 
Response Format  Refer to the `Project Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================


Get Project Information
----------------------------

===============  ===================================
HTTP Method      GET
URI              /*org_name*/all/project/*project_name*
Request Format   *N/A*
Response Format  Refer to the `Project Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
                 | 404 - Not found
===============  ===================================

Partial Updates to a Project
---------------------------------------

Delete a role
~~~~~~~~~~~~~~~

::

    PATCH /VMware/www/project/www
    Host: api.cloudfoundry.com
    Accept: application/json
    Authorization: Bearer h480djs93hd8
    ETag: "a330bc54f0671c9"

    {
        "schemas": "urn:collabspaces:schemas:1.0",
        "roles": [
            { "monitoring": null }
        ]
    }


Add a user to a role
~~~~~~~~~~~~~~~~~~~~~

::

    PATCH /VMware/www/project/www
    Host: api.cloudfoundry.com
    Accept: application/json
    Authorization: Bearer h480djs93hd8
    ETag: "f59f3dr123fhu6"

    {
      "schemas": "urn:collabspaces:schemas:1.0",
      "roles": [
        {
          "monitoring": {
          	"users": ["markl@vmware.com"]
          }
        }
      ]
    }


Remove a user from a role
~~~~~~~~~~~~~~~~~~~~~~~~~~

Since users is a plural attribute, removing a user from the role will require PATCHing the entire
set of users with the updated set.::

    PATCH /VMware/www/project/www
    Host: api.cloudfoundry.com
    Accept: application/json
    Authorization: Bearer h480djs93hd8
    ETag: "f59f3dr123fhu6"

    {
      "schemas": "urn:collabspaces:schemas:1.0",
      "roles": [
        {
          "monitoring": {
          	"users": [
                "jdsa@vmware.com",
                "andrewss@vmware.com"
             ]
          }
        }
      ]
    }

Delete a project in an Org
---------------------------

Deleting a project in an Org will cause all the user assignments in the project as well as the
permission sets to be deleted along with the project itself.

===============  ===================================
HTTP Method      DELETE
URI              /*org_name*/all/project/*project_name*
Request Format   *N/A*
Response Format  *Empty*
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
                 | 404 - Not found
===============  ===================================

Create Resources for an Org
---------------------------------

A resource is associated with an org. Each resource must have a type that is a string decided by the
user. Along with the type, the user can choose to provide metadata for the resource. This may include
any additional information passed as name value pairs that would help in resource management for a 
user. The resource id returned is unique and should be saved to enable querying of the resource, 
for authorization requests etc.


===============  ===================================
HTTP Method      POST
URI              /*org_name*/*proj_name*/*res_type*
Request Format   Refer to the `General Resource Schema`_ 
Response Format  Refer to the `General Resource Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
===============  ===================================

Update Resource information
-----------------------------

This example shows a full update to the collab spaces data for a resource. 
A partial update of a resource can also be done with the HTTP PATCH operation. 
See `partial update`_ resource for more information.

===============  ====================================================
HTTP Method      PUT
URI              /*org_name*/*proj_name*/*res_type*/*res_name*
Request Format   Refer to the `General Resource Schema`_ 
Response Format  Refer to the `General Resource Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
                 | 404 - Not found
===============  ====================================================

Get Resource information
-------------------------

This example shows how to get the collab spaces data of a general resource: 

===============  ====================================================
HTTP Method      GET
URI              /*org_name*/*proj_name*/*res_type*/*res_name*
Request Format   *N/A*
Response Format  Refer to the `General Resource Schema`_ 
Response Codes   | 200 - Operation was successful
                 | 401 - Not Authorized
                 | 404 - Not found
===============  ====================================================

Obtaining an Authorization Decision for Multiple Resources
-----------------------------------------------------------

The following API call may be made to get an authorization decision within Org Acme, Project Demo. The decision is whether the user making the call can read and update the MyDemo app and read the service MyDB. The user will need to be authenticated to the API, see `Authentication to the API`_.

The HTTP response code will indicate the authorization decision.

If any of the resources do not exist, a 404 will be returned.

===============  ========================================
HTTP Method      POST
URI              /Acme/Demo/authorized
Request Format   ::

                    [
                        {
                    	    "name": "MyDemo",
                            "type": "app",
                            "permissionSet": ["READ", "UPDATE"]
                        },
                        {
                        	"name": "MyDB",
                        	"type": "service",
                        	"permissionSet": ["READ"]
                        }
                    ]

Response Format  *Empty*
Response Codes   | 200 - Operation was successful
                 | 400 - Malformed request format
                 | 401 - Not Authorized
                 | 404 - MyDemo or MyDB do not exist
===============  ========================================

The above operation will result in a 200 if the user in the context of ``/Acme/Demo`` can update the MyDemo app and read the MyDB service.

Open Issues
=============

#. If the authorization_endpoint (the URL to the UAA) can be set in an Org via Create, Update, etc., what else needs to happen? If the UAA is going to issue a token just for that Org or CS -- or if this CS needs to authenticate to the UAA, there needs to be some sort of registration with the UAA and shared secret exchanged.

#. How are new resource types and permissions be registered? It could be: a) on the fly, or 2) configuration time.

#. Need to expand examples and explain permission sets. Right now this doc just talks about permissions and only ever uses CRUD in the examples. How are new permission types registered and used?

#. Figure out how to assign permissions/roles to user by email address

#. should be able to make a request to CS for series of auth checks without requesting the operation -- so that apps can not present (or gray out) operations that the user cannot perform. 

#. define API to return all orgs where a user has permissions, and all permissions within an org per user.

#. define API to list all users who have access to an org.

