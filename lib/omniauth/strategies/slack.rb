require 'omniauth/strategies/oauth2'
require 'omniauth-slack/refinements'
require 'omniauth-slack/slack'
require 'omniauth-slack/data_methods'
require 'thread'
require 'uri'

using OmniAuth::Slack::Refinements

module OmniAuth
  module Strategies
    
    class Slack < OmniAuth::Strategies::OAuth2
      
      # Experimental
      include OmniAuth::Slack::DataMethods
    
      AUTH_OPTIONS = %w(redirect_uri scope team team_domain )
      
      option :name, 'slack'
      option :authorize_options, AUTH_OPTIONS - %w(team_domain)
      option :pass_through_params, []
      option :preload_data_with_threads, 0
      # option :include_data, []
      # option :exclude_data, []
      option :additional_data, {}
      option :dependency_filter, /^api_/

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
          scopes: access_token.all_scopes
        }
      end

      info do        
        num_threads, method_names = options.preload_data_with_threads
        if num_threads.to_i > 0
          preload_data_with_threads(num_threads.to_i, method_names || dependencies + options.additional_data.to_h.keys)
        end
     
        # Start with only what we can glean from the authorization response.
        hash = OmniAuth::Slack::Hashy.new(
          name: user_name,
          email: user_email,
          user_id: user_id,
          team_id: team_id,
          team_name: team_name,
          image: image,
          team_domain: team_domain,
          team_image: team_image,
          team_email_domain: team_email_domain,
          nickname: nickname
        )

        # Disabled to manually define info.
        #apply_data_methods(hash)

        # Now add everything else, using further calls to the api, if necessary.
        unless skip_info?
          %w(first_name last_name phone skype avatar_hash real_name real_name_normalized).each do |key|
            hash[key.to_sym] = (
              api_users_info['user'].to_h['profile'] ||
              api_users_profile['profile']
            ).to_h[key]
          end

          %w(deleted status color tz tz_label tz_offset is_admin is_owner is_primary_owner is_restricted is_ultra_restricted is_bot has_2fa).each do |key|
            hash[key.to_sym] = api_users_info['user'].to_h[key]
          end

        end
        hash
      end # info

      extra do
        {
          # scopes_requested: (env['omniauth.params'] && env['omniauth.params']['scope']) || \
          #   (env['omniauth.strategy'] && env['omniauth.strategy'].options && env['omniauth.strategy'].options.scope),
          scopes_requested: scopes_requested,
          web_hook_info: web_hook_info,
          bot_info: access_token['bot'] || api_bots_info['bot'],
          access_token_hash: access_token.to_hash,
          identity: @identity,
          user_info: @api_users_info,
          user_profile: @api_users_profile,
          team_info: @api_team_info,
          additional_data: get_additional_data,
          raw_info: @raw_info
        }
      end
      
      
      # Pass on certain authorize_params to the Slack authorization GET request.
      # See https://github.com/omniauth/omniauth/issues/390
      def authorize_params
        super.tap do |prms|
          digest = prms.hash
          log(:debug, "Using authorize_params #{prms}")
          prms.merge!(request.params.keep_if{|k,v| pass_through_params.reject{|o| o.to_s == 'team_domain'}.include?(k.to_s)})
          log(:debug, "Modified authorize_params #{prms}") if prms.hash != digest
          session['omniauth.authorize_params'] = prms
        end
      end
      
      # Get and decode options[:pass_through_params]. 
      def pass_through_params
        ptp = [options.pass_through_params].flatten.compact
        case
          when ptp[0].to_s == 'all'
            options.pass_through_params = AUTH_OPTIONS
          when ptp[0].to_s == 'none'
            []
          else
            ptp
        end
      end
      
      def callback_phase(*args)
        # This technique copied from OmniAuth::Strategy
        env['omniauth.authorize_params'] = session.delete('omniauth.authorize_params')
        super
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
                
        # Set client#subdomain with custom team_domain, if exists and allowed.
        new_client.subdomain = (pass_through_params.include?('team_domain') && request.params['team_domain']) ? request.params['team_domain'] : options.team_domain
        
        # Put the raw_info in a place where the Client will update it for each API request.
        new_client.history = raw_info
        
        #log(:debug, "Strategy #{self} using Client #{new_client}")
        
        new_client
      end
      
      # Dropping query_string from callback_url prevents some errors in call to /api/oauth.access.
      def callback_url
        full_host + script_name + callback_path
      end
      
      def auth_hash
        define_additional_data #unless skip_info?
        super
      end
      
      
      private
      
      # Define methods for addional data from :additional_data option
      def define_additional_data
        return if @additional_data_defined
        hash = options.additional_data
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
          options.additional_data.to_h.inject({}) do |hash,tupple|
            hash[tupple[0].to_s] = send(tupple[0].to_s)
            hash
          end
        end
      end

      def user_id
        # access_token['user_id'] || access_token['user'].to_h['id'] || access_token['authorizing_user'].to_h['user_id']
        access_token.user_id
      end
      
      def team_id
        # access_token['team_id'] || access_token['team'].to_h['id']
        access_token.team_id
      end

      def user_identity
        @user_identity ||= identity['user'].to_h
      end

      def team_identity
        @team_identity ||= identity['team'].to_h
      end

      def web_hook_info
        #return {} unless access_token.key? 'incoming_webhook'
        access_token['incoming_webhook']
      end

      data_method :identity,
        storage: :identity,
        default_value: {},
        source: [
          # TODO: This line can be simplified by not converting AT to hash.
          {name: :access_token, code: proc{ r = to_hash.select{|k,v| ['user', 'team'].include?(k.to_s)}; r.any? && r} },
          {name: :api_users_identity}
        ]
                    
      data_method :user_name, info_key: 'name', storage: :user_name, source: [
        {name: 'access_token', code: 'user_name'},
        {name: 'user_identity', code: "fetch('name',nil)"},
        {name: 'api_users_info', code: "fetch('user',{}).to_h['real_name']"},
        {name: 'api_users_profile', code: "fetch('profile',{}).to_h['real_name']"}
      ]
      
      data_method :user_email, info_key: 'email', storage: :user_email, source: [
        {name: 'access_token', code: "user_email"},
        {name: 'user_identity', code: "fetch('email',nil)"},
        {name: 'api_users_info', code: "fetch('user',{}).to_h['profile'].to_h['email']"},
        {name: 'api_users_profile', code: "fetch('profile',{}).to_h['email']"}
      ]
      
      data_method :image do
        source(:access_token) { self['team'].to_h['image_34'] }
        source(:user_identity) { to_h['image_34'] }
        source(:api_users_info) { self['user'].to_h['profile'].to_h['image_34'] }
        source(:api_users_profile) { self['profile'].to_h['image_34'] }
      end
      
      data_method :team_name do
        source(:access_token) { team_name }
        source(:team_identity) { to_h['name'] }
        source(:api_team_info) { self['team'].to_h['name'] }
      end
      
      data_method :team_domain do
        source(:access_token) { self['team'].to_h['domain'] }
        source(:team_identity) { to_h['domain'] }
        source(:api_team_info) { self['team'].to_h['domain'] }
      end
      
      data_method :team_image do
        source(:access_token) { self['team'].to_h['image_34'] }
        source(:team_identity) { to_h['image_34'] }
        source(:api_team_info) { self['team'].to_h['icon'].to_h['image_34'] }
      end
            
      data_method :team_email_domain do
        source(:api_team_info) { self['team'].to_h['email_domain'] }
      end
            
      data_method :nickname do
        source(:api_users_info) { to_h['user'].to_h['name'] }
        source(:access_token) { self['user'].to_h['name'] }
        source(:user_identity) { to_h['name'] }
      end

      data_method :api_users_identity,
        scope: {classic:'identity.basic', identity:'identity:read:user'},
        storage: :api_users_identity,
        condition: proc{ true },
        default_value: {},
        source: [
          {name: 'access_token', code: proc{ get('/api/users.identity', headers: {'X-Slack-User' => user_id}).parsed }}
        ]

      data_method :api_users_info do
        default_value Hash.new
        scope classic: 'users:read', team: 'users:read'
        source :access_token do
          get('/api/users.info', params: {user: user_id}, headers: {'X-Slack-User' => user_id}).parsed
        end
      end

      data_method :api_users_profile do
        default_value Hash.new
        scope classic: 'users.profile:read', team: 'users.profile:read'
        source :access_token do
          get('/api/users.profile.get', params: {user: user_id}, headers: {'X-Slack-User' => user_id}).parsed
        end
      end      

      data_method :api_team_info do
        scope classic: 'team:read', team:'team:read'
        default_value Hash.new
        source :access_token do
          get('/api/team.info').parsed
        end
      end
      
      data_method :api_bots_info do
        scope classic: 'users:read', team: 'users:read'
        default_value Hash.new
        source :access_token do
          get('/api/bots.info').parsed
        end
      end
      
      # API call to get user permissions for workspace token.
      # This is needed because workspace token 'sign-in-with-slack' is missing scopes
      # in the :scope field (acknowledged issue in developer preview).
      #
      # Returns [<id>: <resource>]
      #      
      # data_method :api_apps_permissions_users_list do
      #   default_value {}
      #   condition proc { is_app_token? }
      #   source :access_token, 'apps_permissions_users_list(user_id)'
      # end 

      # This hash is handed to the access-token, which in turn fills it with API response objects.
      def raw_info
        @raw_info ||= {}
      end

      # Is this a workspace app token?
      def is_app_token?
        access_token.is_app_token?
      end
      
      def scopes_requested
        #(env['omniauth.params'] && env['omniauth.params']['scope']) || options.scope
        
        # (env['omniauth.authorize_params'].to_h['scope']) ||
        # #(env['omniauth.params'] && env['omniauth.params']['scope']) ||
        # options.scope

        env['omniauth.authorize_params'].to_h['scope']
      end
      
      #   # Scopes come from at least 3 different places now.
      #   # * The classic :scope field (string)
      #   # * New workshop token :scopes field (hash)
      #   # * Call to apps.permissions.users.list (array)
      #   #
      #   # This returns hash of workspace scopes, with classic & new identity scopes in :identity.
      #   # Lists of scopes are in array form.
      #   def all_scopes(*args)
      #     access_token.all_scopes(*args)
      #   end
      
      # Determine if given scopes exist in current authorization.
      # scopes_hash is hash where:
      #   key == scope type <identity|app_home|team|channel|group|mpim|im>
      #   val == array or string of individual scopes.
      # TODO: Something not working here since and/or option was built.
      def has_scope?(scope_query, opts={})
        #opts.merge!(base_scopes: auth_hash.credentials.scope)
        access_token.has_scope?(scope_query, opts)
      end
      
    end # Slack
  end # Strategies
end # OmniAuth

