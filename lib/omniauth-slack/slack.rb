require 'uri'
require 'omniauth-slack/refinements'
require 'omniauth-slack/oauth2/client'
require 'omniauth-slack/oauth2/access_token'

module OmniAuth
  module Slack

    # Build an access token from access-token-hash or from token-string.
    def self.build_access_token(client_id, client_key, token_string_or_hash)
      client = OmniAuth::Slack::OAuth2::Client.new(
        client_id,
        client_key,
        OmniAuth::Strategies::Slack.default_options.client_options.to_h.map{|k,v| [k.to_sym, v]}.to_h
      )
      
      #client.extend Helpers::Client
      #client.options[:raise_errors] = false
      
      access_token = case
        when token_string_or_hash.is_a?(String)
          OmniAuth::Slack::OAuth2::AccessToken.new(client, token_string_or_hash)
        when token_string_or_hash.is_a?(Hash)
          OmniAuth::Slack::OAuth2::AccessToken.from_hash(client, token_string_or_hash)
      end
      
      #access_token.extend Helpers::AccessToken if access_token
      access_token
    end
    
  end
end