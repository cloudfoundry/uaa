#require 'debug'
require 'sinatra/base'
require 'csm/version'
require 'csm/models'

module CSM
  
  CF_INSTANCE_INFO = { 
    :name => 'vcap', 
    :build => "3465a13ab528443f1afcd3c9c2861a078549b8e5", 
    :support => "ac-support@vmware.com", 
    :version => 0.999, 
    :description => "VMware's Cloud Application Platform",
  }
  
  class CSMApp < Sinatra::Base

    set :root, File.expand_path("../../..", __FILE__)
  
    #-------------------------------------------------------------------------
    helpers do
      def select_edit_fields(clss)
        parms = {:name => params[:name]}
        clss.editable_fields.each {|f| parms[f] = params[f]}
        parms
      end
      
      #TODO: either catch and process exceptions or turn them off and handle errors
      def handle_post(clss, container, subsequent_path = request.path_info)
        if !params[:operation]
          @error = "post with no operation parameter"
        elsif params[:operation] == "delete"
          begin
            inst = clss.get(params[:id])
            redirect subsequent_path, 303 if inst && inst.destroy
          rescue Exception => e
            @error = "Could not delete #{clss.display_name} \"#{params[:name]}\", #{e.class}"
          else
            @error = "Could not delete #{clss.display_name} \"#{params[:name]}\". Unknown error"
          end
        elsif params[:operation] == "create"
          begin
            redirect subsequent_path, 303 if container.create select_edit_fields(clss)
          rescue DataObjects::IntegrityError => e
            @error = "Could not create #{clss.display_name} \"#{params[:name]}\". Duplicate name?"
          else
            @error = "Could not create #{clss.display_name} \"#{params[:name]}\". Unknown error"
          end
        else
          @error = "unknown operation in post"
        end
        erb :show_error
      end
      
      def set_user_instance
        unless @instnce = User.first(:name => params[:username])
          @error = "No user named #{params[:username]}"
          return false
        end
        true
      end

      def set_org_instance
        unless @instnce = Org.first(:name => params[:orgname])
          @error = "No organization named #{params[:orgname]}"
          return false
        end
        true
      end

      def set_project_instance
        unless @org = Org.first(:name => params[:orgname])
          @error = "No organization named #{params[:orgname]}"
          return false
        end
        unless @instnce = @org.projects.first(:name => params[:projname])
          @error = "No project named #{params[:projname]} in #{params[:orgname]}"
          return false
        end
        true
      end
      
      def get_info(info)
        if request.accept.index 'application/json' 
          return info.to_json
        end
        @reply_info = info
        erb :show_info
      end
    end

    #-------------------------------------------------------------------------
    get '/' do
      @paragraph_text = "collaboration spaces POC<br>" +
        "root: #{settings.root}<br>" +
        "public: #{settings.public}<br>" +
        "static: #{settings.static}<br>" +
        "<br><a href=\"/users\">Users</a><br>" + 
        "<br><a href=\"/orgs\">Organizations</a><br>"
      erb :show_paragraph
    end
    
    #-------------------------------------------------------------------------
    # info
    get '/info' do
      get_info CF_INSTANCE_INFO.dup
    end

    #-------------------------------------------------------------------------
    # Orgs
    get '/orgs/?' do
      @table_info = { :class => Org, :entries => Org.all, :post_path => '/orgs' }
      erb :table_edit
    end
  
    post '/orgs' do
      handle_post Org, Org
    end
    
    post '/orgs/:orgname/users/:username/tokens' do
      halt 410
    end

    #-------------------------------------------------------------------------
    # Users
    get '/users/?' do
      @table_info = { :class => User, :entries => User.all, :post_path => '/users' }
      erb :table_edit
    end
  
    post '/users' do
      handle_post User, User
    end

    get '/users/info' do
      get_info CF_INSTANCE_INFO.dup.merge :prompt => {
          :email => [:text,"CloudFoundry ID (Email)"],
          :password => [:password,"CloudFoundry Password"],
          :vmw_username => [:text,"VMware Username (not email)"],
          :vmw_password => [:password,"WMware Password"],
          :vmw_password => [:auth_code,"Auth Code"],
        }
    end
    
    #-------------------------------------------------------------------------
    # specific org
    get '/orgs/:orgname' do
      return erb :show_error unless set_org_instance
      erb :show_org
    end
    
    get '/orgs/:orgname/info' do
      return erb :show_error unless set_org_instance
      get_info CF_INSTANCE_INFO.dup.merge :org => @instnce.name, 
        :prompt => {
          :email => [:text,"CloudFoundry ID (Email)"],
          :password => [:password,"CloudFoundry Password"],
          :vmw_username => [:text,"VMware Username (not email)"],
          :vmw_password => [:password,"WMware Password"]
        }
    end
    
    #-------------------------------------------------------------------------
    # specific user
    get '/users/:username' do
      return erb :show_error unless set_user_instance
      @table_info = { :class => Emailaddr, :entries => @instnce.emailaddrs.all, :no_entry_links => true, :post_path => "#{request.path_info}/emailaddrs" }
      erb :show_user
    end
    
    post '/users/:username/emailaddrs' do
      return erb :show_error unless set_user_instance
      handle_post Emailaddr, @instnce.emailaddrs, "/users/#{params[:username]}"
    end

    post '/users/:username/tokens' do
      return erb :show_error unless set_user_instance
      handle_post Emailaddr, @instnce.emailaddrs, "/users/#{params[:username]}"
    end

    #-------------------------------------------------------------------------
    # specific projects
    get '/:orgname/:projname' do
      return erb :show_error unless set_project_instance
      @table_info_rolemap = { :class => Rolemap, :entries => @instnce.rolemaps.all, :post_path => "#{request.path_info}/rolemaps" }
      @table_info_projects = params[:projname] == "all"? { :class => Project, :entries => @org.projects.all, :post_path => "#{request.path_info}/projects" }: nil
      @table_info_groups = { :class => Group, :entries => @instnce.groups.all, :post_path => "#{request.path_info}/groups" }
      @table_info_apps = { :class => App, :entries => @instnce.apps.all, :post_path => "#{request.path_info}/apps" }
      @table_info_services = { :class => Service, :entries => @instnce.services.all, :post_path => "#{request.path_info}/services" }
      erb :project
    end

    post '/:orgname/:projname/rolemaps' do
      return erb :show_error unless set_project_instance
      handle_post Rolemap, @instnce.rolemaps, "/#{params[:orgname]}/#{params[:projname]}"
    end

    post '/:orgname/:projname/groups' do
      return erb :show_error unless set_project_instance
      handle_post Group, @instnce.groups, "/#{params[:orgname]}/#{params[:projname]}"
    end

    post '/:orgname/:projname/apps' do
      return erb :show_error unless set_project_instance
      handle_post App, @instnce.apps, "/#{params[:orgname]}/#{params[:projname]}"
    end

    post '/:orgname/:projname/services' do
      return erb :show_error unless set_project_instance
      handle_post Service, @instnce.services, "/#{params[:orgname]}/#{params[:projname]}"
    end

    post '/:orgname/:projname/projects' do
      return erb :show_error unless set_project_instance
      handle_post Project, @org.projects, "/#{params[:orgname]}/#{params[:projname]}"
    end

  end
end
#==========================================================================

