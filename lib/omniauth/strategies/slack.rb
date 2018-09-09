require 'omniauth/strategies/oauth2'
require 'omniauth-slack/helpers'
require 'thread'
require 'uri'

module OmniAuth
  module Strategies
    
    class Slack < OmniAuth::Strategies::OAuth2
    
      option :name, 'slack'
      option :authorize_options, [:scope, :team, :team_domain, :redirect_uri]
      option :preload_data_with_threads, 0
      option :include_data, []
      option :exclude_data, []
      option :additional_data, {}

      option :client_options, {
        site: 'https://slack.com',
        token_url: '/api/oauth.access',
        auth_scheme: :basic_auth
      }
      
      option :auth_token_params, {
        mode: :query,
        param_name: 'token'
      }
      
      # User ID is not guaranteed to be globally unique across all Slack users.
      # The combination of user ID and team ID, on the other hand, is guaranteed
      # to be globally unique.
      uid { "#{user_id}-#{team_id}" }

      credentials do
        {
          token_type: access_token['token_type'],
          scope: access_token['scope'],
          scopes: all_scopes #((user_id if scopes_requested.to_s[/identity/]))
        }
      end

      info do        
        num_threads = options.preload_data_with_threads.to_i
        if num_threads > 0  # && !skip_info?
          preload_data_with_threads(num_threads)
        end
      
        # Start with only what we can glean from the authorization response.
        hash = { 
          name: access_token['user'].to_h['name'],
          email: access_token['user'].to_h['email'],
          user_id: user_id,
          team_name: access_token['team_name'] || access_token['team'].to_h['name'],
          team_id: team_id,
          image: access_token['team'].to_h['image_48']
        }

        # Now add everything else, using further calls to the api, if necessary.
        unless skip_info?
          %w(first_name last_name phone skype avatar_hash real_name real_name_normalized).each do |key|
            hash[key.to_sym] = (
              user_info['user'].to_h['profile'] ||
              user_profile['profile']
            ).to_h[key]
          end

          %w(deleted status color tz tz_label tz_offset is_admin is_owner is_primary_owner is_restricted is_ultra_restricted is_bot has_2fa).each do |key|
            hash[key.to_sym] = user_info['user'].to_h[key]
          end

          more_info = {
            image: (
              hash[:image] ||
              user_identity.to_h['image_48'] ||
              user_info['user'].to_h['profile'].to_h['image_48'] ||
              user_profile['profile'].to_h['image_48']
              ),
            name:(
              hash[:name] ||
              user_identity['name'] ||
              user_info['user'].to_h['real_name'] ||
              user_profile['profile'].to_h['real_name']
              ),
            email:(
              hash[:email] ||
              user_identity.to_h['email'] ||
              user_info['user'].to_h['profile'].to_h['email'] ||
              user_profile['profile'].to_h['email']
              ),
            team_name:(
              hash[:team_name] ||
              team_identity.to_h['name'] ||
              team_info['team'].to_h['name']
              ),
            team_domain:(
              access_token['team'].to_h['domain'] ||
              team_identity.to_h['domain'] ||
              team_info['team'].to_h['domain']
              ),
            team_image:(
              access_token['team'].to_h['image_44'] ||
              team_identity.to_h['image_44'] ||
              team_info['team'].to_h['icon'].to_h['image_44']
              ),
            team_email_domain:(
              team_info['team'].to_h['email_domain']
              ),
            nickname:(
              user_info.to_h['user'].to_h['name'] ||
              access_token['user'].to_h['name'] ||
              user_identity.to_h['name']
              ),
          }
          
          hash.merge!(more_info)
        end
        hash
      end # info

      extra do
        {
          # scopes_requested: (env['omniauth.params'] && env['omniauth.params']['scope']) || \
          #   (env['omniauth.strategy'] && env['omniauth.strategy'].options && env['omniauth.strategy'].options.scope),
          scopes_requested: scopes_requested,
          web_hook_info: web_hook_info,
          bot_info: access_token['bot'] || bot_info['bot'],
          access_token_hash: access_token.to_hash,
          identity: identity,
          user_info: user_info,
          user_profile: user_profile,
          team_info: team_info,
          additional_data: get_additional_data,
          raw_info: @raw_info
        }
      end

      
      # Extend AccessToken instance with helpers.
      def access_token(*args)
        at = super
        unless at.singleton_class.ancestors.include?(OmniAuth::Slack::Helpers::AccessToken)
          log(:debug, "Extending #{at} with additional functionality.")
          at.extend OmniAuth::Slack::Helpers::AccessToken
        end
        at
      end
      
      # Pass on certain authorize_params to the Slack authorization GET request.
      # See https://github.com/omniauth/omniauth/issues/390
      def authorize_params
        super.tap do |params|
          %w(scope team redirect_uri).each do |v|
            if !request.params[v].to_s.empty?
              params[v.to_sym] = request.params[v]
            end
          end
          log(:debug, "Authorize_params #{params.to_h}")
        end
      end
      
      # Get a new OAuth2::Client and define custom behavior.
      # * overrides previous omniauth-strategies-oauth2 :client definition.
      #
      # * Log API requests with OmniAuth.logger
      # * Add API responses to @raw_info hash
      # * Set auth site uri with custom subdomain (if provided).
      #
      def client
        new_client = super
        new_client.extend OmniAuth::Slack::Helpers::Client
        
        # Set client#site with custom team_domain, if exists.
        new_client.subdomain = request.params['team_domain'] || options[:team_domain]
        
        # Put the raw_info in a place where the Client will update it for each API request.
        new_client.history = raw_info
        
        log(:debug, "Strategy #{self} using Client #{new_client}")
        
        new_client
      end
      
      # Dropping query_string from callback_url prevents some errors in call to /api/oauth.access.
      def callback_url
        full_host + script_name + callback_path
      end
      
      def user_info
        return {} unless !skip_info? && is_not_excluded? && has_scope?(classic:'users:read', team:'users:read')
        semaphore.synchronize {
          @user_info ||= access_token.get('/api/users.info', params: {user: user_id}, headers: {'X-Slack-User' => user_id}).parsed
        }
      end
      
      def auth_hash
        define_additional_data #unless skip_info?
        super
      end
      
      
      private
      
      def initialize(*args)
        super
        @main_semaphore = Mutex.new
        @semaphores = {}
      end
      
      # Get a mutex specific to the calling method.
      # This operation is synchronized with its own mutex.
      def semaphore(method_name = caller[0][/`([^']*)'/, 1])
        @main_semaphore.synchronize {
          @semaphores[method_name] ||= Mutex.new
        }
      end
      
      def active_methods
        @active_methods ||= (
          includes = [options.include_data].flatten.compact
          excludes = [options.exclude_data].flatten.compact unless includes.size > 0
          method_list = %w(apps_permissions_users_list identity user_info user_profile team_info bot_info)  #.concat(options[:additional_data].keys)
          if includes.size > 0
            method_list.keep_if {|m| includes.include?(m.to_s) || includes.include?(m.to_s.to_sym)}
          elsif excludes[0].to_s == 'all'
            method_list = []
          elsif excludes.size > 0
            method_list.delete_if {|m| excludes.include?(m.to_s) || excludes.include?(m.to_s.to_sym)}
          end
          log :debug, "Activated API calls: #{method_list}."
          log :debug, "Activated additional_data calls: #{options.additional_data.keys}."
          method_list
        )
      end
      
      def is_not_excluded?(method_name = caller[0][/`([^']*)'/, 1])
        active_methods.include?(method_name.to_s) || active_methods.include?(method_name.to_s.to_sym)
      end
      
      # Preload additional api calls with a pool of threads.
      def preload_data_with_threads(num_threads)
        return unless num_threads > 0 && !@preloaded_data
        @preloaded_data = 1
        preload_methods = active_methods + options[:additional_data].keys
        log :info, "Preloading (#{preload_methods.size}) data requests using (#{num_threads}) threads."
        work_q = Queue.new
        preload_methods.each{|x| work_q.push x }
        workers = num_threads.to_i.times.map do
          Thread.new do
            begin
              while x = work_q.pop(true)
                log :debug, "Preloading #{x} in thread #{Thread.current.object_id}."
                send x
              end
            rescue ThreadError
            end
          end
        end
        workers.map(&:join); "ok"
      end
      
      # Define methods for addional data from :additional_data option
      def define_additional_data
        return if @additional_data_defined
        hash = options[:additional_data]
        if !hash.to_h.empty?
          hash.each do |k,v|
            define_singleton_method(k) do
              instance_variable_get(:"@#{k}") || 
              instance_variable_set(:"@#{k}", v.respond_to?(:call) ? v.call(env) : v)
            end
          end
          @additional_data_defined = 1
        end
      end
      
      def get_additional_data
        if false && skip_info?
          {}
        else
          options[:additional_data].inject({}) do |hash,tupple|
            hash[tupple[0].to_s] = send(tupple[0].to_s)
            hash
          end
        end
      end
      
      def identity
        return {} unless !skip_info? && is_not_excluded? && has_scope?(classic:'identity.basic', identity:'identity:read:user')
        semaphore.synchronize {
          @identity ||= access_token.get('/api/users.identity', headers: {'X-Slack-User' => user_id}).parsed
        }
      end

      def user_identity
        @user_identity ||= identity['user'].to_h
      end

      def team_identity
        @team_identity ||= identity['team'].to_h
      end
      
      def user_profile
        return {} unless !skip_info? && is_not_excluded? && has_scope?(classic:'users.profile:read', team:'users.profile:read')
        semaphore.synchronize {
          @user_profile ||= access_token.get('/api/users.profile.get', params: {user: user_id}, headers: {'X-Slack-User' => user_id}).parsed
        }
      end

      def team_info
        return {} unless !skip_info? && is_not_excluded? && has_scope?(classic:'team:read', team:'team:read')
        semaphore.synchronize {
          @team_info ||= access_token.get('/api/team.info').parsed
        }
      end

      def web_hook_info
        #return {} unless access_token.key? 'incoming_webhook'
        access_token['incoming_webhook']
      end
      
      def bot_info
        return {} unless !skip_info? && is_not_excluded? && has_scope?(classic:'users:read', team:'users:read')
        semaphore.synchronize {
          @bot_info ||= access_token.get('/api/bots.info').parsed
        }
      end
      
      def user_id
        access_token['user_id'] || access_token['user'].to_h['id'] || access_token['authorizing_user'].to_h['user_id']
      end
      
      def team_id
        access_token['team_id'] || access_token['team'].to_h['id']
      end

      def raw_info
        @raw_info ||= {}
      end
      
      # API call to get user permissions for workspace token.
      # This is needed because workspace token 'sign-in-with-slack' is missing scopes
      # in the :scope field (acknowledged issue in developer preview).
      #
      # Returns [<id>: <resource>]
      def apps_permissions_users_list(user=nil)
        return {} unless is_not_excluded? && is_app_token?  # && !skip_info?
        # semaphore.synchronize {
        #   @apps_permissions_users_list ||= access_token.apps_permissions_users_list
        #   user_id ? @apps_permissions_users_list[user_id].to_h['scopes'] : @apps_permissions_users_list
        # }
        access_token.apps_permissions_users_list(user)
      end
      
      def scopes_requested
        (env['omniauth.params'] && env['omniauth.params']['scope']) || options.scope
      end
      
      # Is this a workspace app token?
      def is_app_token?
        access_token.is_app_token?
      end
      
      # Scopes come from at least 3 different places now.
      # * The classic :scope field (string)
      # * New workshop token :scopes field (hash)
      # * Call to apps.permissions.users.list (array)
      #
      # This returns hash of workspace scopes, with classic & new identity scopes in :identity.
      # Lists of scopes are in array form.
      def all_scopes(*args)
        access_token.all_scopes(*args)
      end
      
      # Determine if given scopes exist in current authorization.
      # scopes_hash is hash where:
      #   key == scope type <identity|app_home|team|channel|group|mpim|im>
      #   val == array or string of individual scopes.
      # TODO: Something not working here since and/or option was built.
      def has_scope?(scope_query, **opts)
        access_token.has_scope?(scope_query, **opts)
      end
      
    end
  end
end

