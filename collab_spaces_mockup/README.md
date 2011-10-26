# Collaboration Spaces Mockup

This is experimental code, is not complete, and may never be complete. 

This project is intended to provide a mockup of the proposed collaboration 
spaces model. It should provide DataMapper models for the various entity
types such as Org, User, Group, Project, Application, and Service. The 
endpoints can be accessed with a browser, or via REST APIs (to the same)
endpoints if the content type is JSON. 

The intention is to help us visualize how Orgs, Groups, and Projects could 
interact with Users, Apps and Services -- and how the relations could be 
structured in the most intuitive way. 

You can run the tests with Rake (though there are not many tests yet)

    $ rake test

or run the server with

	$ ruby lib/csm

With the server running, you can access it from a browser at localhost:4567, 
or via curl.



