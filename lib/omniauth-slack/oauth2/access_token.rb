require 'oauth2/access_token'
require 'omniauth-slack/semaphore'

module OmniAuth
  module Slack
    module OAuth2
      class AccessToken < ::OAuth2::AccessToken
        prepend Slack::Semaphore

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
        def apps_permissions_users_list(_user_id=nil)
          #raise StandardError, "APUL caller #{caller[0][/`([^']*)'/, 1]} user #{_user_id}"
          return {} unless is_app_token?
          semaphore.synchronize {
            @apps_permissions_users_list ||= (
              r = get('/api/apps.permissions.users.list').parsed
              r['resources'].to_a.inject({}){|h,i| h[i['id']] = i; h} || {}
            )
            _user_id ? @apps_permissions_users_list[_user_id].to_h['scopes'] : @apps_permissions_users_list
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
        def all_scopes(_user_id=nil)
          if _user_id && !@all_scopes.to_h.has_key?('identity') || @all_scopes.nil?
            @all_scopes = (
              scopes = case
                when params['scope']
                  {'classic' => params['scope'].split(/[, ]+/)}
                when params['scopes']
                  params['scopes']
                when is_app_token?
                  apps_permissions_scopes_list
              end
              
              scopes['identity'] = apps_permissions_users_list(_user_id) if _user_id && is_app_token?
              params['scopes'] = scopes
            )
          else
            @all_scopes
          end
        end
      
        # Determine if given scopes exist in current authorization.
        # This is classic and worspace token compatible (TODO: does this accept all slack token types?).
        # scope_query is a hash where:
        #   key == scope type <app_home|team|channel|group|mpim|im|identity|classic>
        #   val == array or string of individual scopes.
        #   opts ==
        #     user_id
        #     base_scopes
        #     logic
        #
        def has_scope?(scope_query, opts={})
          #puts "HasScope: #{scope_query} with opts: '#{opts}'"
          # if scope_query.is_a?(Array) && scope_query[0].is_a?(Array)
          #   puts "Processing list of scope queries"
          #   return scope_query.all?{|query| puts "Processing scope query: #{query}"; has_scope?(*query)}
          # end
          opts ||= {}         
          user = opts[:user_id] || user_id
          scope_query = [scope_query].flatten
          #puts "AccessToken#has_scope with user '#{user}' scope_query '#{scope_query}' opts '#{opts}'"
          
          logic = case
            when opts[:logic].to_s.downcase == 'or'; {outter: 'all?', inner: 'any?'}
            when opts[:logic].to_s.downcase == 'and'; {outter: 'any?', inner: 'all?'}
            else {outter: 'all?', inner: 'any?'}
          end
          #puts "Scope Logic #{logic.inspect}"
          
          scope_query.send(logic[:outter]) do |query|
            #puts "Outter Scope Query: #{query.inspect}"
          
            base_scopes = case
              when opts[:base_scopes]
                #puts "Base Scopes: opts[:base_scopes]"
                opts[:base_scopes]
              when user && query.is_a?(Hash) && query.keys.detect{|k| k.to_s == 'identity'}
                #puts "Base Scopes: all_scopes(user)"
                all_scopes(user)
              else
                #puts "Base Scopes: all_scopes"
                all_scopes
            end
  
            query.send(logic[:inner]) do |section, scopes|
              test_scopes = case
                when scopes.is_a?(String); scopes.split(/[, ]+/)
                when scopes.is_a?(Array); scopes
                else raise "Scope data must be a string or array of strings, like this {team: 'chat:write,team:read', channels: ['channels:read', 'chat:write']}"
              end
              #puts "TESTING with base_scopes: #{base_scopes.to_yaml}"
              
              test_scopes.send(logic[:inner]) do |scope|
                #puts "Inner Scope Query section: #{section.to_s}, scope: #{scope}"
                base_scopes.to_h[section.to_s].to_a.include?(scope.to_s)
              end
            end
            
          end # scope_query.each
        end # has_scope?
        
      end # AccessToken
    end
  end
end