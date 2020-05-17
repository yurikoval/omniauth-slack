require 'oauth2/client'
require 'oauth2/response'
require 'omniauth'
require 'omniauth-slack/debug'
require 'omniauth-slack/oauth2/access_token'
require 'omniauth-slack/omniauth/auth_hash'

module OmniAuth
  module Slack
    module OAuth2
      class Client < ::OAuth2::Client
        
        include OmniAuth::Slack::Debug
        
        #using StringRefinements
        #using OAuth2Refinements
        
        # If this is an array, request history will be stored.
        # Only store request history if each Client instance is relatively short-lived.
        #
        # From your app, you can set this:
        #   OmniAuth::Slack::OAuth2::Client::HISTORY_DEFAULT ||= []
        #
        # Then, in your authorization callback action, you can direct
        # the OAuth2::Client request history to the AuthHash#['extra']['raw_info']:
        #   @auth_hash = env['omniauth.auth']
        #   @access_token = env['omniauth.strategy'].access_token
        #   @access_token.client.history = @auth_hash.extra.raw_info
        #
        # TODO: The above seems a little messy. Maybe use a proc
        #       to rediredct Client request history to wherever.
        #       Or maybe don't offer any history storage at all.
        #
        HISTORY_DEFAULT=nil
      
        attr_accessor :logger, :history, :subdomain
        
        def initialize(*args)
          debug{"args: #{args}"}
          super
          self.logger = OmniAuth.logger
          self.history ||= HISTORY_DEFAULT.dup
        end
                
        # Overrides OAuth2::Client#get_token to pass in the omniauth-slack AccessToken class.
        def get_token(params, access_token_opts = {}, access_token_class = OmniAuth::Slack::OAuth2::AccessToken) # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
          debug{"params #{params}, access_token_opts #{access_token_opts}"}
          rslt = super(params, access_token_opts, access_token_class)
          debug{"Client #{self} built AccessToken #{rslt}"}
          rslt
        end
        
        # Logs each API request and stores the API result in History array (if exists).
        # TODO: There should be some kind of option to disable this.
        def request(*args)
          logger.debug "(slack) API request '#{args[0..1]}'."  # in thread '#{Thread.current.object_id}'."  # by Client '#{self}'
          debug{"API request args #{args}"}
          request_output = super(*args)
          uri = args[1].to_s.gsub(/^.*\/([^\/]+)/, '\1') # use single-quote or double-back-slash for replacement.
          if history.is_a?(Array)
            debug{"Saving response to history object #{history.object_id}"}
            history << OmniAuth::Slack::AuthHash.new(
              {api_call: uri.to_s, time: Time.now, response: request_output}
            )
          end
          #debug{"API response (#{args[0..1]}) #{request_output.class}"}
          debug{"API response #{request_output.response.env.body}"}
          request_output
        end

        # Overrides #site to insert custom subdomain for API calls.
        def site(*args)
          if !@subdomain.to_s.empty?
            site_uri = URI.parse(super)
            site_uri.host = "#{@subdomain}.#{site_uri.host}"
            logger.debug "(slack) Oauth site uri with custom team_domain #{site_uri}"
            site_uri.to_s
          else
            super
          end
        end
        
      end
    end
  end
end