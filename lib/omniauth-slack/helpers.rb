require 'uri'

module OmniAuth
  module Slack
  
    def self.ad_hoc_access_token(client_id, client_key, token_string_or_hash)
      client = ::OAuth2::Client.new(
        client_id,
        client_key,
        OmniAuth::Strategies::Slack.default_options['client_options'].map{|k,v| [k.to_sym, v]}.to_h
      )
      
      client.extend Helpers::Client
      client.options[:raise_errors] = false
      
      access_token = case
        when token_string_or_hash.is_a?(String)
          ::OAuth2::AccessToken.new(client, token_string_or_hash)
        when token_string_or_hash.is_a?(Hash)
          ::OAuth2::AccessToken.from_hash(client, token_string_or_hash)
      end
      
      access_token.extend Helpers::AccessToken if access_token
      access_token
    end
    
        
    module Helpers
      module Client
        def self.extended(other)
          other.instance_eval do
            singleton_class.send :attr_accessor, :logger, :history, :subdomain
            
            #options[:raise_errors] = false
            
            self.logger = Logger.new(STDOUT)
            self.history = {}
          end
        end
            
        def request(*args)
          logger.send(:debug, "(slack) API request #{args[0..1]}")  #; by Client #{self}; in thread #{Thread.current.object_id}.")
          request_output = super(*args)
          uri = args[1].to_s.gsub(/^.*\/([^\/]+)/, '\1') # use single-quote or double-back-slash for replacement.
          history[uri.to_s] = request_output
          request_output
        end
        
        def subomain=(sd)
          if !sd.to_s.empty?
            site_uri = URI.parse site
            site_uri.host = "#{sd}.slack.com"
            self.site = site_uri.to_s
            logger.send(:debug, "Oauth site uri with custom team_domain #{site_uri}")
            site
          end
        end      
      end # Client    
    
    
      module AccessToken
      
        def self.extended(other)
          other.instance_eval do
            @main_semaphore = Mutex.new
            @semaphores = {}
          end
        end
        
        # Get a mutex specific to the calling method.
        # This operation is synchronized with its own mutex.
        def semaphore(method_name = caller[0][/`([^']*)'/, 1])
          @main_semaphore.synchronize {
            @semaphores[method_name] ||= Mutex.new
          }
        end
      
        def user_id
          params['authorizing_user'].to_h['user_id'] ||
          params['user'].to_h['id']
        end
        
        def team_id
          params['team_id'] ||
          params['team'].to_h['id']
        end
        
        def uid
          "#{user_id}-#{team_id}"
        end
      
        # Is this a workspace app token?
        def is_app_token?
          case
            when params['token_type'] == 'app' || token.to_s[/^xoxa/]
              true
            when token.to_s[/^xoxp/]
              false
            else
              nil
          end
        end
      
        def apps_permissions_users_list
          #return {}
          semaphore.synchronize {
            @apps_permissions_users_list ||= (
              get('/api/apps.permissions.users.list')
            ).parsed['resources'].to_h.inject({}){|h,i| h[i['id']] = i; h}
          }
        end
        
        def apps_permissions_scopes_list
          return {} unless is_app_token?
            semaphore.synchronize {
            @apps_permissions_scopes_list ||= (
              get('/api/apps.permissions.scopes.list')
            ).parsed['scopes']
          }
        end
        
        def all_scopes
          @all_scopes ||=
          {'identity' => (params['scope'] || apps_permissions_users_list[user_id].to_h['scopes'].to_a.join(',')).to_s.split(',')}
          .merge(params['scopes'] || apps_permissions_scopes_list || {})
        end
      
        # Determine if given scopes exist in current authorization.
        # scopes_hash is hash where:
        #   key == scope type <identity|app_home|team|channel|group|mpim|im>
        #   val == array or string of individual scopes.
        def has_scope?(_logic=:'or', _all_scopes=all_scopes, scopes_hash)
          #OmniAuth.logger.debug("AccessToken#hash_scope? with logic:'#{_logic}', all-scopes:'#{_all_scopes}', scopes-hash:'#{scopes_hash}'")
          !scopes_hash.is_a?(Hash) && scopes_hash = {'identity'=>scopes_hash}
          logic = case
            when _logic.to_s.downcase == 'or'; :'any?'
            when _logic.to_s.downcase == 'and'; :'all?'
            else :'any?'
          end
          _all_scopes ||= all_scopes
          scopes_hash.send(logic) do |section, scopes|
            test_scopes = case
              when scopes.is_a?(String); scopes.split(/[, ]/)
              when scopes.is_a?(Array); scopes
              else raise "Scope must be a string or array"
            end
            test_scopes.send(logic) do |scope|
              _all_scopes[section.to_s].to_a.include?(scope.to_s)
            end
          end
        end
        
        def refresh!(*args)
          new_token = super
          new_token.extend Helpers::AccessToken
          new_token
        end
            
      end # AccessToken
    end # Helpers
  
  end # Slack
end # OmniAuth

