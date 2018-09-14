require 'oauth2/access_token'

module OmniAuth
  module Slack
    module OAuth2
      class AccessToken < ::OAuth2::AccessToken
        
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

        %w(user_name user_email team_id team_name team_domain).each do |word|
          obj, atrb = word.split('_')
          define_method(word) do
            params[word] ||
            params[obj].to_h[atrb]
          end
        end

        def user_id
          params['user_id'] ||
          params['user'].to_h['id'] ||
          params['authorizing_user'].to_h['user_id']
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
        
        # Is this a token returned from an identity-scoped request?
        def is_identity_token?
          params['user_id'] ||
          params['user'].to_h['id']
        end
      
        # Parsed identity scopes (workspace apps only).
        def apps_permissions_users_list(user=nil)
          return {} unless is_app_token?
          semaphore.synchronize {
            @apps_permissions_users_list ||= (
              r = get('/api/apps.permissions.users.list').parsed
              r['resources'].to_a.inject({}){|h,i| h[i['id']] = i; h} || {}
            )
            user ? @apps_permissions_users_list[user].to_h['scopes'] : @apps_permissions_users_list
          }
        end
        
        # Hash of current scopes for this token (workspace apps only).
        def apps_permissions_scopes_list
          return {} unless is_app_token?
            semaphore.synchronize {
            @apps_permissions_scopes_list ||= (
              r = get('/api/apps.permissions.scopes.list').parsed
              r['scopes'] || {}
            )
          }
        end
                
        # Get all scopes, including apps.permissions.users.list if user_id.
        # This now puts all compiled scopes back into params['scopes']
        def all_scopes(user=nil)
          if user && !@all_scopes.to_h.has_key?('identity') || @all_scopes.nil?
            @all_scopes = (
              scopes = case
                when params['scope']
                  {'classic' => params['scope'].split(/[, ]/)}
                when params['scopes']
                  params['scopes']
                when is_app_token?
                  apps_permissions_scopes_list
              end
              
              scopes['identity'] = apps_permissions_users_list(user) if user && is_app_token?
              params['scopes'] = scopes
            )
          else
            @all_scopes
          end
        end
      
        # Determine if given scopes exist in current authorization.
        # scope_query is a hash where:
        #   key == scope type <app_home|team|channel|group|mpim|im|identity|classic>
        #   val == array or string of individual scopes.
        #
        def has_scope?(scope_query, **opts)          
          user = opts[:user_id] || user_id
          base_scopes = case
            when opts[:base_scopes]
              opts[:base_scopes]
            when user && scope_query.is_a?(Hash) && scope_query.keys.detect{|k| k.to_s == 'identity'}
              all_scopes(user)
            else
              all_scopes
          end
          
          logic = case
            when opts[:logic].to_s.downcase == 'or'; :'any?'
            when opts[:logic].to_s.downcase == 'and'; :'all?'
            else :'any?'
          end

          scope_query.send(logic) do |section, scopes|
            test_scopes = case
              when scopes.is_a?(String); scopes.split(/[, ]/)
              when scopes.is_a?(Array); scopes
              else raise "Scope must be a string or array"
            end
            #puts "TESTING with base_scopes: #{base_scopes.to_yaml}"
            
            test_scopes.send(logic) do |scope|
              #puts "TESTING section: #{section.to_s}, scope: #{scope}"
              base_scopes.to_h[section.to_s].to_a.include?(scope.to_s)
            end
          end
        end
        
#         def refresh!(*args)
#           new_token = super
#           new_token.extend Helpers::AccessToken
#           new_token
#         end        

      end
    end
  end
end