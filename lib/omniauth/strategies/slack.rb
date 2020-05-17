require 'omniauth/strategies/oauth2'
require 'omniauth-slack/refinements'
require 'omniauth-slack/slack'
require 'omniauth-slack/data_methods'
require 'omniauth-slack/omniauth/auth_hash'
require 'thread'
require 'uri'

module OmniAuth
  using Slack::OAuth2Refinements
  
  module Strategies
    class Slack < OmniAuth::Strategies::OAuth2
      include OmniAuth::Slack::Debug 
      
      # This is a forward-declaration (or is just an override?),
      # so that AuthHash is NOT derived directly from the base OmniAuth::AuthHash.
      class AuthHash < OmniAuth::Slack::AuthHash;
      end
      
      
      ###  Options  ###
    
      debug{"#{self} setting up default options"}
      
      # Master list of authorization options handled by omniauth-slack.
      # See below for redirect_uri.
      AUTH_OPTIONS = %i(scope user_scope team team_domain)
      
      # Default strategy name.
      option :name, 'slack'
      
      # Options that can be passed with provider authorization URL.
      option :authorize_options, AUTH_OPTIONS - %i(team_domain)
      
      # OAuth2::Client options.
      option :client_options, {
        site: 'https://slack.com',
        #authorize_url: proc{"/oauth/#{@options[:flow_version]=='v2' ? 'v2/' : ''}authorize"},
        authorize_url: '/oauth/v2/authorize',
        #token_url: proc{"/api/oauth.#{@options[:flow_version]=='v2' ? 'v2.' : ''}access"},
        token_url: '/api/oauth.v2.access',
        auth_scheme: :basic_auth,
        raise_errors: false, # MUST be false to allow Slack's non-compliant get-token response in v2 flow.
      }
      
      # Authorization token-exchange API call options.
      option :auth_token_params, {
        mode: :query,
        param_name: 'token'
      }


      ###  Omniauth Slack custom options  ###
      
      # redirect_uri does not need to be in authorize_options,
      # since it inserted anyway by omniauth-oauth2 during both
      # the request (authorization) phase and the callback (get-token) phase.
      # The magic of redirect_uri actually happens in the callback_url method.
      option :redirect_uri
      
      # Options allowed to pass from omniauth /auth/<provider> URL
      # to provider authorization URL.
      option :pass_through_params, %i(team)
    

      ###  Data  ###
      
      # User ID is not guaranteed to be globally unique across all Slack users.
      # The combination of user ID and team ID, on the other hand, is guaranteed
      # to be globally unique.
      #
      #uid { "#{user_id}-#{team_id}" }
      uid { access_token&.uid }


      # Gathers access_token and awarded scopes for :credentials section of AuthHash.
      #
      credentials do
        {
          token_type: access_or_user_token&.token_type,
          scope: access_or_user_token&.scope,
          scopes: access_or_user_token&.all_scopes,
          token: access_or_user_token&.token
        }
      end

      # Gathers a myriad of possible data returned from omniauth-slack /api/oauth.access call,
      # for :info section of AuthHash.
      #
      # You an modify the info hash from your application.
      # This example adds a users_info API request and response.
      # Note that this will automatically store Client request history,
      # if enabled. You do not need to link the auth-hash raw-info to
      # the Client history array (See notes in OmniAuth::Slack::OAuth2::Client).
      #
      # Example:
      #
      #   class OmniAuth::Strategies::Slack
      #     original_info = info.dup
      #     info do
      #       {
      #         access_token: instance_exec(&original_info),
      #         users_info: access_token.get('/api/users.info', params: {user: access_token.user_id}, headers: {'X-Slack-User' => (access_token.user_id)}).parsed
      #       }
      #     end
      #   end
      #
      info do        
        access_token.to_hash
      end # info


      # Gathers additiona API calls, user-defined additional_data_method responses, and raw Slack API responses,
      # for :extra section of AuthHash.
      #
      extra do
        {
          scopes_requested: scopes_requested,
          raw_info: raw_info
        }
      end
      
      # Overrides OmniAuth::Oauth2#authorize_params so that
      # specified params can be passed on to Slack authorization GET request.
      # See https://github.com/omniauth/omniauth/issues/390
      #
      def authorize_params
        super.tap do |prms|
          params_digest = prms.hash
          debug{"Using authorize_params #{prms}"}
          prms.merge!(request.params.keep_if{|k,v| pass_through_params.reject{|o| o.to_s == 'team_domain'}.include?(k.to_s)})
          log(:debug, "Modified authorize_params #{prms}") if prms.hash != params_digest
          session['omniauth.authorize_params'] = prms
        end
      end
      
      # Overrides OmniAuth callback phase to extract session var
      # for omniauth.authorize_params into env (this is how omniauth does this).
      def callback_phase #(*args)
        # This technique copied from OmniAuth::Strategy (this is how they do it for the other omniauth objects).
        env['omniauth.authorize_params'] = session.delete('omniauth.authorize_params')
                
        #   # This is trying to help move additiona_data definition away from user-action.
        #   self.class.define_additional_data(options.additional_data)
        
        result = super
      end
      
      # Overrides OmniAuth::Strategies::OAuth2#client to define custom behavior.
      #
      # * Logs API requests with OmniAuth.logger.
      # * Adds API responses to @raw_info hash.
      # * Sets auth site uri with custom subdomain (if provided).
      #
      # Returns instance of custom OmniAuth::Slack::OAuth2::Client.
      #
      def client
        #new_client = super
        
        # Simple override to use our custom subclassed OAuth2::Client instead.
        # The Client.new call is lifted directly from OmniAuth::Strategies::OAuth2.
        new_client = OmniAuth::Slack::OAuth2::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
               
        # Set client#subdomain with custom team_domain, if exists and allowed.
        new_client.subdomain = (pass_through_params.include?('team_domain') && request.params['team_domain']) ? request.params['team_domain'] : options.team_domain
        
        #   # Put the raw_info in a place where the Client will update it for each API request.
        #   new_client.history = raw_info
        
        debug{"Strategy #{self} using Client #{new_client}"}
        
        new_client
      end

      # Dropping query_string from callback_url prevents some errors in call to /api/oauth.[v2.]access.
      #
      def callback_url
        options.redirect_uri || full_host + script_name + callback_path
      end

      
      private
      
      def user_id
        # access_token['user_id'] || access_token['user'].to_h['id'] || access_token['authorizing_user'].to_h['user_id']
        access_or_user_token&.user_id
      end

      def team_id
        access_token&.team_id
      end
      
      # Gets and decodes :pass_through_params option.
      #
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

      # Parsed data returned from /slack/oauth.[v2.]access api call.
      #
      # Where does this actually go? Where is it used?
      #
      # Simplifying this to just 'access_token.to_hash' does not appear to
      # have any noticeable negative effect.
      #
      def auth
        @auth ||= access_token.to_hash
      end


      # This hash is handed to the access-token (or is it the AuthHash?), which in turn fills it with API response objects.
      #
      def raw_info
        @raw_info ||= access_token.client.history
        debug{"Retrieved raw_info (size #{@raw_info.size}) (object_id #{@raw_info.object_id})"}
        @raw_info
      end
      
      # Gets 'authed_user' sub-token from main access token.
      #
      def user_token
        access_token&.user_token
      end
      
      # Gets main access_token, if valid, otherwise gets user_token, if valid.
      # Handles Slack v1 and v2 API (v2 is non-conformant with OAUTH2 spec).
      def access_or_user_token
        if access_token&.token
          access_token
        elsif user_token
          user_token
        else
          access_token
        end
      end
      
      def scopes_requested
        # omniauth.authorize_params is a custom enhancement to omniauth for omniauth-slack.
        out = {
          scope: env['omniauth.authorize_params'].to_h['scope'],
          user_scope: env['omniauth.authorize_params'].to_h['user_scope']
        }
        
        debug{"scopes_requested: #{out}"}
        return out
      end

      # Convenience method for user.
      def has_scope?(*args)
        access_or_user_token.has_scope?(*args)
      end
      
    end # Slack
  end # Strategies
end # OmniAuth

