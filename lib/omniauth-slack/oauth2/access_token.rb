require 'oauth2/access_token'
require 'omniauth-slack/refinements'
require 'omniauth-slack/data_methods'
require 'omniauth-slack/debug'

module OmniAuth
  module Slack
    using StringRefinements
    
    module OAuth2
      class AccessToken < ::OAuth2::AccessToken        
        include OmniAuth::Slack::DataMethods
        include OmniAuth::Slack::Debug
                
        # This is automatic if DataMethods are included.
        #require 'omniauth-slack/semaphore'
        #prepend Slack::Semaphore
        
        # Experimental:
        # Needed to copy Strategy data-methods to access-token without any modification.
        def access_token; self; end

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
          #raise StandardError, "APUL caller #{caller_method_name} user #{_user_id}"
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
                  {'classic' => params['scope'].words}
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
      
        # AccessToken instance has_scope?
        # Determine if given scopes exist on the current access token.
        # This is classic and workspace token compatible.
        # TODO: does this accept all slack token types?
        # scope_query is a hash where:
        #   key == scope type <app_home|team|channel|group|mpim|im|identity|classic>
        #   val == array or string of individual scopes.
        #   opts ==
        #     user_id
        #     base_scopes
        #     logic
        # If scope_query is a string, it will be interpreted as {classic: scope_query}
        #
        def has_scope?(scope_query, opts={})
          debug{"HasScope: #{scope_query} with opts: '#{opts}'"}
          # Experimental: accept array of scope-query arrays.
          # I don't think we want to do this.
          # if scope_query.is_a?(Array) && scope_query[0].is_a?(Array)
          #   puts "Processing list of scope queries"
          #   return scope_query.all?{|query| puts "Processing scope query: #{query}"; has_scope?(*query)}
          # end
          opts ||= {}         
          user = opts[:user_id] || user_id
          scope_query = [scope_query].flatten
          debug{"AccessToken#has_scope with user '#{user}' scope_query '#{scope_query}' opts '#{opts}'"}
          
          logic = opts[:logic] || 'or'
          
          scope_base = case
            when opts[:base_scopes]
              debug{"Base Scopes: opts[:base_scopes]"}
              opts[:base_scopes]
            #when user && query.is_a?(Hash) && query.keys.detect{|k| k.to_s == 'identity'}
            when user && scope_query.detect{ |q| q.is_a?(Hash) && q.keys.detect{|k| k.to_s == 'identity'} }
              debug{"Base scopes using: all_scopes(user)"}
              all_scopes(user)
            else
              debug{"Base scopes using: all_scopes"}
              all_scopes
          end
          
          self.class.has_scope?(scope_query: scope_query, scope_base: scope_base, logic: logic)
        end # has_scope?
        
                
        # Class-level has_scope? with no token or state dependencies.
        # Match the given scope_query against the given scope_base, with the given logic.
        # This is classic and workspace token compatible.
        # TODO: Remove any code specific to Slack, like classic-vs-workspace handling.
        # scope_query is a hash (or array of hashes) where:
        #   key == scope type <app_home|team|channel|group|mpim|im|identity|classic>
        #   val == array or string of individual scopes.
        #   logic == 'and' or 'or' (default).
        # If scope_query is a string, it will be interpreted as {classic: scope_query}
        # TODO: Can this be added to OAuth2::AccessToken as a generic has_scope? Would it work for other providers?
        #
        def self.has_scope?(scope_query:{}, scope_base:{}, logic:'or')
          debug{"AccessToken.has_scope? scope_query '#{scope_query}' scope_base '#{scope_base}' logic '#{logic}'"}
          _scope_query = scope_query.is_a?(String) ? {classic: scope_query} : scope_query
          _scope_query = [_scope_query].flatten
          _scope_base  = scope_base
          
          _logic = case
            when logic.to_s.downcase == 'or'; {outter: 'all?', inner: 'any?'}
            when logic.to_s.downcase == 'and'; {outter: 'any?', inner: 'all?'}
            else {outter: 'all?', inner: 'any?'}
          end
          debug{"Scope Logic #{_logic.inspect}"}
          
          _scope_query.send(_logic[:outter]) do |query|
            debug{"Outter Scope Query: #{_scope_query.inspect}"}

            query.send(_logic[:inner]) do |section, scopes|
              test_scopes = case
                when scopes.is_a?(String); scopes.words
                when scopes.is_a?(Array); scopes
                else raise "Scope data must be a string or array of strings, like this {team: 'chat:write,team:read', channels: ['channels:read', 'chat:write']}"
              end
              
              test_scopes.send(_logic[:inner]) do |scope|
                debug{"Inner Scope Query section: #{section.to_s}, scope: #{scope}"}
                _scope_base.to_h[section.to_s].to_a.include?(scope.to_s)
              end
            end
            
          end # scope_query.each
        end # self.has_scope?
        
      end # AccessToken
    end
  end
end