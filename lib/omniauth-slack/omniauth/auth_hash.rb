require 'omniauth'

module OmniAuth
  module Slack
    class AuthHash < OmniAuth::AuthHash
      include Hashie::Extensions::DeepFind
    end
  end
end