require 'oauth2/client'
require 'omniauth'
require 'omniauth-slack/oauth2/access_token'

module OmniAuth
  module Slack
    module OAuth2
      class Client < ::OAuth2::Client
      
        attr_accessor :logger, :history, :subdomain
        
        def initialize(*args)
          super
          self.logger = OmniAuth.logger
          self.history = {}
        end
                
        # Override the OAuth2::Client#get_token to pass in the omniauth-slack AccessToken.
        def get_token(params, access_token_opts = {}, access_token_class = OmniAuth::Slack::OAuth2::AccessToken) # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
          rslt = super(params, access_token_opts, access_token_class)
          logger.debug "(slack) Client #{self} using AccessToken #{rslt}"
          rslt
        end
        
        # Log each request and store the result in @history hash.
        def request(*args)
          logger.debug "(slack) API request #{args[0..1]}"  #; by Client #{self}; in thread #{Thread.current.object_id}.")
          request_output = super(*args)
          uri = args[1].to_s.gsub(/^.*\/([^\/]+)/, '\1') # use single-quote or double-back-slash for replacement.
          history[uri.to_s] = request_output
          #logger.debug "(slack) API response (#{args[0..1]}) #{request_output.parsed}"
          request_output
        end

        # Use custom subdomain for oauth.access calls.
        def site(*args)
          if !@subdomain.to_s.empty?
            site_uri = URI.parse(super)
            site_uri.host = "#{@subdomain}.#{site_uri.host}"
            logger.debug "(slack) Oauth site uri with custom team_domain #{site_uri}"
            site_uri
          else
            super
          end
        end
        
      end
    end
  end
end