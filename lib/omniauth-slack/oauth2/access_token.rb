# :markup: tomdoc

require 'oauth2/access_token'
require 'omniauth-slack/refinements'
require 'omniauth-slack/data_methods'
require 'omniauth-slack/debug'

# The AccessToken object is built from an access-token-hash, which is returned from the get-token
# API request or is passed in manually via AccessToken.from_hash(). See OmniAuth::Slack::build_access_token.
#
# The original access-token hash can always be found at AccessToken#params.
# As a convenience, you can call '[]' on the params hash by sending
# the method and args directly to the access-token object.
#
#     my_token['ok']      --> true
#     my_token['app_id']  --> A012345678
#
# The AccessToken object moves some things around a little bit, for example: The params['access_token']
# string is moved to the top level of the access-token object under the method 'token'.
#
#     my_token.token      --> xoxb-123456789...
#
# For workspace-app tokens, you will see a 'scopes' hash in access-token data.
# You can use the hash if you want, but you can also just call my_token.all_scopes.
# Tokens that have no inherent 'scopes' hash from Slack, will have it inserted based
# on the 'scope' string.
# 
# See Slack's documentation on the different types of tokens available.
#
#     https://api.slack.com/methods/oauth.access
#     https://api.slack.com/methods/oauth.v2.access
#
#
module OmniAuth
  module Slack
    using StringRefinements
    using OAuth2Refinements
    
    module OAuth2
      # Enhanced subclass of OAuth2::AccessToken, used by OmniAuth::Slack
      # whenever an OAuth2::AccessToken is required.
      #
      # Adds class and instance scope-query method +has_scope?+, and adds
      # basic API data methods and access methods.
      class AccessToken < ::OAuth2::AccessToken        
        include OmniAuth::Slack::DataMethods
        include OmniAuth::Slack::Debug

        # AccessToken instance (self), so Strategy data-methods can be copied to AccessToken without modification.
        def access_token; self; end
        
        # Intercept super to return nil instead of empty string.
        def token
          rslt = super
          rslt.to_s == '' ? nil : rslt
        end
        
        def token_type
          params['token_type'] ||
          case
            when params['access_token'].to_s[/xoxp/]; 'user'
            when params['access_token'].to_s[/xoxb/]; 'bot'
            when params['access_token'].to_s[/xoxa/]; 'app'
            when params['access_token'].to_s[/xoxr/]; 'refresh'
          end
        end
        
        def token_type?(*_type)
          #debug{"'#{_type}'"}
          [_type].flatten.any? do |t|
            token_type.to_s == t.to_s
          end
        end
        
        # Converts 'authed_user' hash (of Slack v2 oauth flow) to AccessToken object.
        # Use this to call API methods from a user-token.
        def user_token
          @user_token ||= (
            if token_type?('user')
              self
            elsif params['authed_user']
              rslt = self.class.from_hash(client, params['authed_user']).tap do |t|
                t.params['token_type'] = 'user'
              end
            end
          )
        end
        alias_method :authed_user, :user_token

        # Creates simple getter methods to pull specific data from params.
        %w(user_name user_email team_id team_name team_domain scope).each do |word|
          obj, atrb = word.split('_')
          define_method(word) do
            params[word] ||
            params[obj].to_h[atrb] #||
          end
        end

        # Cannonical AccessToken user_id.
        def user_id
          # classic token.
          params['user_id'] ||
          # v2 api bot token.
          params['bot_user_id'] ||
          # user-id from authed_user hash.
          params['id'] ||
          # workspace-app token with attached user.
          params['user'].to_h['id'] ||
          # workspace-app token with authorizing user.
          params['authorizing_user'].to_h['user_id'] #||
          # if still no id found, pull from the sub-token 'authed_user'.
          # TODO: I don't think we should do this, since it will be out
          # of sync with the other methods and data on this token instance.
          #params['authed_user'].to_h['id']
        end
        
        def bot_user_id
          params['bot_user_id']
        end
        
        # Cannonical AccessToken unique user-team-id combo.
        def uid
          "#{user_id}-#{team_id}"
        end
        
        def bot_uid
          bot_user_id ? "#{bot_user_id}-#{team_id}" : nil
        end  
        
        data_method :api_users_identity,
          scope: {classic:'identity.basic', identity:'identity:read:user'},
          storage: :api_users_identity,
          #condition: proc{ true },
          condition: proc{ token_type? 'user' },
          default_value: {},
          source: [
            {name: 'access_token', code: proc{ get('/api/users.identity', headers: {'X-Slack-User' => user_id}).parsed }}
          ]
                    
        data_method :api_users_info do
          default_value AuthHash.new
          scope classic: 'users:read', team: 'users:read'
          source :access_token do |*args|
            puts "api_users_info args[0]: #{args[0]}"
            get('/api/users.info', params: {user: (args[0] || user_id)}, headers: {'X-Slack-User' => (args[0] || user_id)}).to_auth_hash
          end
        end
  
        data_method :api_users_profile do
          default_value AuthHash.new
          scope classic: 'users.profile:read', team: 'users.profile:read'
          source :access_token do
            get('/api/users.profile.get', params: {user: user_id}, headers: {'X-Slack-User' => user_id}).to_auth_hash
          end
        end      
  
        data_method :api_team_info do
          scope classic: 'team:read', team:'team:read'
          default_value Hash.new
          source :access_token do
            get('/api/team.info').parsed
          end
        end
        
        # Info about bots on the token's team, NOT info about a bot token from v2 API.
        data_method :api_bots_info do
          scope classic: 'users:read', team: 'users:read'
          #condition { !is_app_token? }
          condition { ! token_type?('app') }
          default_value Hash.new
          source :access_token do
            get('/api/bots.info').parsed
          end
        end
        
      
        # Identity scopes (workspace apps only).
        # Given _user_id, returns specific identity scopes.
        #
        # Sets @apps_permissions_users_list with parsed API response.
        #
        # _user_id  - String of Slack user ID.
        #
        def apps_permissions_users_list(_user_id=nil)
          #raise StandardError, "APUL caller #{caller_method_name} user #{_user_id}"
          #return {} unless is_app_token?
          return {} unless token_type?('app')
          semaphore.synchronize {
            @apps_permissions_users_list ||= (
              r = get('/api/apps.permissions.users.list').parsed
              r['resources'].to_a.inject({}){|h,i| h[i['id']] = i; h} || {}
            )
            _user_id ? @apps_permissions_users_list[_user_id].to_h['scopes'] : @apps_permissions_users_list
          }
        end
        
        # Hash of current scopes for this token (workspace apps only).
        # NOTE: Workspace apps are deprecated!
        #
        # Sets +@apps_permissions_scopes_list+ with parsed API response.
        def apps_permissions_scopes_list
          #return {} unless is_app_token?
          return {} unless token_type?('app')
            semaphore.synchronize {
            @apps_permissions_scopes_list ||= (
              r = get('/api/apps.permissions.scopes.list').parsed
              r['scopes'] || {}
            )
          }
        end
                
        # Compiles scopes awarded to this AccessToken.
        # Given _user_id, includes +apps.permissions.users.list+.
        #
        # Sets +@all_scopes+ with parsed API response.
        #
        # This now puts all compiled scopes back into <tt>params['scopes']</tt>,
        # but only if token is workspace-app token.
        # 
        # _user_id  - String of Slack user ID.
        #
        # Returns Hash of scope Arrays where *key* is scope section
        # and *value* is Array of scopes.
        #
        def all_scopes(_user_id=nil)
          #debug{"_user_id: #{_user_id}, @all_scopes: #{@all_scopes}"}
          if _user_id && !@all_scopes.to_h.has_key?('identity') || @all_scopes.nil?
            
            @all_scopes = (
              scopes = case
                # when params['scope'] && token_type? 'bot'
                #   {'bot' => params['scope'].words}
                # when params['scope'] && token_type? 'user'
                #   {'user' => params['scope'].words}
                when ! params['scope'].to_s.empty?
                  {'classic' => params['scope'].words}
                when params['scopes'].to_h.any?
                  params['scopes']
                #when is_app_token?
                when token_type?('app')
                  apps_permissions_scopes_list
                else
                  #{}
              end
              
              #scopes['identity'] = apps_permissions_users_list(_user_id) if _user_id && is_app_token?
              scopes['identity'] = apps_permissions_users_list(_user_id) if _user_id && token_type?('app')
              params['scopes'] = scopes if token_type?('app')
              scopes
            )
            
          else
            @all_scopes
          end
          
          #debug{"generated #{@all_scopes}"}
          @all_scopes
        end
        
        # Match a given set of scopes against this token's awarded scopes,
        # classic and workspace token compatible.
        #
        # If the scope-query is a string, it will be interpreted as a Slack Classic App
        # scope string +{classic: scope-query-string}+, even if the token is a v2 token.
        #
        # The keywords need to be symbols, so any hash passed as an argument
        # (or as the entire set of args) should have symbolized keys!
        #
        # freeform_array    - [*Array, nil] default: [], array of scope query hashes
        #
        # :query            - [Hash, Array, nil] default: nil, a single scope-query Hash (or Array of Hashes)
        #
        # :logic            - [String, Symbol] default: 'or' [:or | :and] logic for the scope-query.
        #                     Applies to a single query hash.
        #                     The reverse logic is applied to an array of query hashes.
        #
        # :user             - [String] (nil) default: nil, user_id of the Slack user to query against
        #                     leave blank for non-user queries
        #
        # :base             - [Hash] default: nil, a set of scopes to query against
        #                     defaults to the awarded scopes on this token
        #
        # freeform_hash     - [**Hash] default: {}, interpreted as single scope query hash
        #
        # TODO: Does this accept all slack token types? What about bot tokens? Others?
        #
        def has_scope?(*freeform_array, query: nil, logic:'or', user:nil, base:nil, **freeform_hash)
          #OmniAuth.logger.debug({freeform_array:freeform_array, freeform_hash:freeform_hash, query:query, logic:logic, user:user, base:base})
          debug{{freeform_array:freeform_array, freeform_hash:freeform_hash, query:query, logic:logic, user:user, base:base}}
          
          query ||= case
            #when simple_string; {classic: simple_string}
            when freeform_array.any?; freeform_array
            when freeform_hash.any?; freeform_hash
          end
          return unless query
          
          query = [query].flatten if query.is_a?(Array) || query.is_a?(String)
          query = {classic: query} if query.is_a?(Array) && query.first.is_a?(String)
          
          user ||= user_id
          debug{"using user '#{user}' and query '#{query}'"}
          
          is_identity_query = case query
            when Hash
              query.keys.detect{|k| k.to_s == 'identity'}
            when Array
              query.detect{ |q| q.is_a?(Hash) && q.keys.detect{|k| k.to_s == 'identity'} }
          end
          
          base ||= case
            when user && is_identity_query
              #debug{"calling all_scopes(user=#{user}) to build base-scopes"}
              all_scopes(user)
            else
              #debug{"calling all_scopes to build base-scopes"}
              all_scopes
          end
          
          #debug{{freeform_array:freeform_array, freeform_hash:freeform_hash, query:query, logic:logic, user:user, base:base}}
          self.class.has_scope?(scope_query:query, scope_base:base, logic:logic)
        end
        
        # Matches the given scope_query against the given scope_base, with the given logic.
        #
        # This is classic and workspace token compatible.
        #
        # keywords      - All arguments are keyword arguments:
        #
        # :scope_query  - [Hash, Array of hashes] default: {}.
        #                 If scope_query is a string, it will be interpreted as +{classic: scope-query-string}+.
        #
        #                 key    - Symbol of scope type <app_home|team|channel|group|mpim|im|identity|classic>
        #                 value  - Array or String of individual scopes
        #
        # :scope_base   - [Hash] defaul: {}, represents the set of scopes to query against.
        #
        # :logic        - [String, Symbol] default: or. One of <and|or>.
        #                 Applies to a single query hash.
        #                 The reverse logic is applied to an array of query hashes.
        #
        # Examples
        #                 
        #   has_scope?(scope_query: {channel: 'channels:read chat:write'})
        #   has_scope?(scope_query: [{identity:'uers:read', channel:'chat:write'}, {app_home:'chat:write'}], logic:'and')
        #   has_scope?(scope_query: 'identity:users identity:team identity:avatar')
        #
        # TODO: Remove any code specific to Slack, like classic-vs-workspace handling.
        #
        # TODO: Can this be added to OAuth2::AccessToken as a generic has_scope? Would it work for other providers?
        # It ~should~ work for other providers, according to oauth2 spec https://tools.ietf.org/html/rfc6749#section-3.3
        #
        def self.has_scope?(scope_query:{}, scope_base:{}, logic:'or')
          debug{"class-level scope_query '#{scope_query}' scope_base '#{scope_base}' logic '#{logic}'"}
          _scope_query = scope_query.is_a?(String) ? {classic: scope_query} : scope_query
          _scope_query = [_scope_query].flatten
          _scope_base  = scope_base
          raise "scope_base must be a hash" unless (_scope_base.is_a?(Hash) || _scope_base.respond_to?(:to_h))
          
          out=false
          
          _logic = case
            when logic.to_s.downcase == 'or'; {outter: 'all?', inner: 'any?'}
            when logic.to_s.downcase == 'and'; {outter: 'any?', inner: 'all?'}
            else {outter: 'all?', inner: 'any?'}
          end
          debug{"_logic #{_logic.inspect}"}
          debug{"_scope_query #{_scope_query}"}
          
          _scope_query.send(_logic[:outter]) do |query|
            debug{"outter query: #{_scope_query.inspect}"}

            query.send(_logic[:inner]) do |section, scopes|
              test_scopes = case
                when scopes.is_a?(String); scopes.words
                when scopes.is_a?(Array); scopes
                else raise "Scope data must be a string or array of strings, like this {team: 'chat:write,team:read', channels: ['channels:read', 'chat:write']}"
              end
              
              test_scopes.send(_logic[:inner]) do |scope|
                debug{"inner query section: #{section.to_s}, scope: #{scope}"}
                out = _scope_base.to_h[section.to_s].to_a.include?(scope.to_s)
              end
            end
            
          end # scope_query.send outter-query
          debug{"output: #{out}"}
          return out
          
        end # self.has_scope?
        
      end # AccessToken
    end
  end
end