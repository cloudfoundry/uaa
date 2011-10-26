require 'datamapper'

#DataMapper::Logger.new($stdout, :debug)
DataMapper::setup(:default, "sqlite3://#{Dir.pwd}/collab_spaces.db")
DataMapper::Model.raise_on_save_failure = true

module CSM

#------------------------------------------------------------------------------
# Orgs

  class Org
    include DataMapper::Resource
    property :id, Serial
    property :name, String, :required => true, :unique_index => true
    property :description, String
    property :created_at, DateTime
    property :last_seen_at, DateTime

    has n, :groups
    has n, :services
    has n, :apps
    has n, :projects

    after :create, :add_defaults
    def add_defaults
        projects.create :name => "all", :description => "the default base project"
    end

    def self.editable_fields; [:description]; end
    def self.display_fields; [:created_at, :last_seen_at]; end
    def self.display_name; "Organization Name"; end

  end
  
  class Emailaddr
    include DataMapper::Resource
    property :id, Serial
    property :name, String, :unique_index => :per_user
    property :validated, Boolean, :default => false
    property :primary, Boolean, :default => true
    property :created_at, DateTime
    property :validated_at, DateTime
    property :user_id, Integer, :unique_index => :per_user #ugly workaround to get foreign key in the compound index
    belongs_to :user
    def self.editable_fields; []; end
    def self.display_fields; [:primary, :created_at, :validated_at]; end
    def self.display_name; "Email Address"; end
  end
  
  class User
    include DataMapper::Resource
    property :id, Serial
    property :name, String, :required => true, :unique_index => true
    property :description, String
    property :created_at, DateTime
    property :last_seen_at, DateTime
    property :password, String

    has n, :emailaddrs
    has n, :groups, :through => Resource

    def self.editable_fields; [:description, :password]; end
    def self.display_fields; [:created_at, :last_seen_at]; end
    def self.display_name; "User Name"; end
  end
 
#------------------------------------------------------------------------------
# Resources: Apps, Groups, Services, Projects
# TODO: should be unique within an org, or perhaps within a org/resource_type?

  class Group
    include DataMapper::Resource
    property :id, Serial
    property :created_at, DateTime
    property :name, String, :required => true, :unique_index => :per_org
    property :description, String

    property :org_id, Integer, :unique_index => :per_org #ugly workaround to get foreign key in the compound index
    belongs_to :org

    has n, :users, :through => Resource
    has n, :projects, :through => Resource

    def self.editable_fields; [:description]; end
    def self.display_fields; [:created_at]; end
    def self.display_name; "Group"; end
  end
 
  class Service
    include DataMapper::Resource
    property :id, Serial
    property :created_at, DateTime
    property :name, String, :required => true, :unique_index => :per_org
    property :description, String

    property :org_id, Integer, :unique_index => :per_org #ugly workaround to get foreign key in the compound index
    belongs_to :org

    has n, :projects, :through => Resource

    def self.editable_fields; [:description]; end
    def self.display_fields; [:created_at]; end
    def self.display_name; "Service"; end
  end
   
  class App
    include DataMapper::Resource
    property :id, Serial
    property :created_at, DateTime
    property :name, String, :required => true, :unique_index => :per_org
    property :description, String

    property :org_id, Integer, :unique_index => :per_org #ugly workaround to get foreign key in the compound index
    belongs_to :org

    has n, :projects, :through => Resource

    def self.editable_fields; [:description]; end
    def self.display_fields; [:created_at]; end
    def self.display_name; "Application"; end
  end

#------------------------------------------------------------------------------
# Project and related classes
   
  class Permset
    include DataMapper::Resource
    property :id, Serial
    property :created_at, DateTime
    property :perms, Integer, :min => 0, :max => 7

    belongs_to :rolemap

    #todo: should be polymorphic link to any resource?
    belongs_to :group
    belongs_to :app
    belongs_to :service
    belongs_to :project
  end
   
  class Rolemap
    include DataMapper::Resource
    property :id, Serial
    property :name, String, :required => true, :unique_index => :per_proj
    property :description, String
    property :created_at, DateTime
    has n, :users, :through => Resource
    has n, :groups, :through => Resource
    has n, :permsets
    property :project_id, Integer, :unique_index => :per_proj #ugly workaround to get foreign key in the compound index
    belongs_to :project
    def self.editable_fields; []; end
    def self.display_fields; [:created_at]; end
    def self.display_name; "Project Roles"; end
  end

  class Project
    include DataMapper::Resource
    property :id, Serial
    property :created_at, DateTime
    property :name, String, :required => true, :unique_index => :per_org
    property :description, String
    has n, :rolemaps
    has n, :groups, :through => Resource
    has n, :apps, :through => Resource
    has n, :services, :through => Resource
    property :org_id, Integer, :unique_index => :per_org #ugly workaround to get foreign key in the compound index
    belongs_to :org
    def self.editable_fields; [:description]; end
    def self.display_fields; [:created_at]; end
    def self.display_name; "Project Name"; end
  end

#------------------------------------------------------------------------------
   
end 

DataMapper.finalize
DataMapper.auto_upgrade!
#DataMapper.auto_migrate!
