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
      
        attr_accessor :logger, :history, :subdomain
        
        def initialize(*args)
          debug{"OmniAuth::Slack::Client#initialize args: #{args}"}
          super
          self.logger = OmniAuth.logger
          self.history = {}
        end
                
        # Overrides OAuth2::Client#get_token to pass in the omniauth-slack AccessToken.
        def get_token(params, access_token_opts = {}, access_token_class = OmniAuth::Slack::OAuth2::AccessToken) # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
          rslt = super(params, access_token_opts, access_token_class)
          debug{"Client #{self} using AccessToken #{rslt}"}
          rslt
        end
        
        # Logs each API request and stores the API result in @history hash.
        # TODO: There should be some kind of option to disable this.
        def request(*args)
          logger.debug "(slack) API request '#{args[0..1]}'."  # in thread '#{Thread.current.object_id}'."  # by Client '#{self}'
          request_output = super(*args)
          uri = args[1].to_s.gsub(/^.*\/([^\/]+)/, '\1') # use single-quote or double-back-slash for replacement.
          history[uri.to_s] = request_output
          debug{"API response (#{args[0..1]}) #{request_output.class}"}
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

        # Overrides #authorize_url to handle a proc (allowing influence from flow_version).
        def authorize_url(*args)
          if options[:authorize_url].is_a?(Proc)
            options[:authorize_url] = instance_eval &(options[:authorize_url])
          end
          super
        end
        
        # Overrides #token_url to handle a proc (allowing influence from flow_version).
        def token_url(*args)
          if options[:token_url].is_a?(Proc)
            options[:token_url] = instance_eval &(options[:token_url])
          end
          super
        end
        
      end
    end
  end
end