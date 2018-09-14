require 'omniauth-slack/oauth2/client'

# Refinements will work as long as the call to the refined method is lexically scoped with the 'using'.

module OmniAuth
  module Slack
    module Refinements
      
      refine OmniAuth::Strategies::OAuth2 do
        def client
          OAuth2::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
        end
      end
      
    end
  end
end