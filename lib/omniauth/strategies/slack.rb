require 'omniauth/strategies/oauth2'
require 'uri'
require 'rack/utils'

module OmniAuth
  module Strategies
  
    # See https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema for more
    # info on the auth_hash schema (is this doc still valid?).
    # 
    # Note that Slack does not consider email to be an essential field, and
    # therefore does not guarantee inclusion of email data in either the
    # signin-with-slack or the add-to-slack flow. Omniauth, however, considers
    # email to be a required field. So adhearing to omniauth's spec means
    # either forcing certain Slack scopes or always making multiple api
    # requests for each authorization, which breaks (or renders useless)
    # omniauth's skip_info feature. This version of omniauth-slack respects
    # the skip_info feature: if set, only a single api request will be made
    # for each authorization. The response of this request may or
    # may not contain email data.
    # 
    # Requested scopes (not the actual token scopes) can be found during
    # the callback in env['omniauth.strategy']['options']['scope'].
    # Actual token scopes can be found in the AuthHash object.
    # 
    # Slack is designed to allow quick authorization of users with minimally
    # scoped requests. Deeper scope authorizations are intended to be aquired
    # with further passes thru Slack's authorization process, as the needs of
    # the user and the endpoint app require. This works because Slack scopes
    # are additive - once you successfully authorize a scope, the token will
    # possess that scope forever, regardless of what flow or scopes are
    # requested at future authorizations. Removal of scopes requires revocation
    # of the token.
    # 
    # Other noteable features of this omniauth-slack version.
    # 
    # * Use compound user-team uid.
    # 
    # * Incude complete token scope in credentials section of auth_hash.
    # 
    # * Use any/all user & team api methods to gather additional informaion,
    #   regardless of the current request scope. Which api requests are used is
    #   determined by the requirements of the auth_hash and the token's full
    #   set of authorized scopes.
    # 
    # * In the extra:raw_info section, return as much of each api response as
    #   possible for all api requests made for the current authorization
    #   cycle. Possible calls are oauth.access, users.info, team.info,
    #   users.identity, users.profile.get, and bots.info. An attempt is made
    #   to use as few api requests as possible.
    #
    # * Allow setting of Slack subdomain at runtime.
    #
    # * Allow option to preload the above mentioned api responses using
    #   any number of pooled threads.
    #
    #   In the provider setup block:
    #
    #     provider :slack,
    #       key,
    #       secret,
    #       :preload_data_with_threads => 3
    #
    #   The default (0) skips this feature and behaves as mentioned above.
    #   Any integer > 0 will use that number of threads to preload the five
    #   mentioned api responses (as permitted by the token's scopes).
    #
    class Slack < OmniAuth::Strategies::OAuth2
      option :name, 'slack'

      option :authorize_options, [:scope, :team, :team_domain]

      option :client_options, {
        site: 'https://slack.com',
        token_url: '/api/oauth.access'
      }

      # Add team_domain to site subdomain if provided in auth url or strategy options. 
      option :setup, lambda{|env|
        strategy = env['omniauth.strategy']
        team_domain = strategy.request.params['team_domain'] || strategy.options[:team_domain]
        strategy.options[:client_options].site = (
          !team_domain.to_s.empty? ? "https://#{team_domain}.slack.com" : "https://slack.com"
        )
      }
      
      option :auth_token_params, {
        mode: :query,
        param_name: 'token'
      }
      
      option :preload_data_with_threads, 0

      # User ID is not guaranteed to be globally unique across all Slack users.
      # The combination of user ID and team ID, on the other hand, is guaranteed
      # to be globally unique.
      uid { "#{user_id}-#{team_id}" }
      
      credentials do
        {
          #token: access_token.token,
          token: auth['token'],
          scope: (is_app_token ? all_scopes : auth['scope']),
          expires: false
        }
      end

      info do
        #puts "Requesting info"
        
        num_threads = options.preload_data_with_threads.to_i
        if num_threads > 0 && !skip_info?
          preload_data_with_threads(num_threads)
        end
      
        # Start with only what we can glean from the authorization response.
        hash = { 
          name: auth['user'].to_h['name'],
          email: auth['user'].to_h['email'],
          user_id: user_id,
          team_name: auth['team_name'] || auth['team'].to_h['name'],
          team_id: team_id,
          image: auth['team'].to_h['image_48']
        }

        # Now add everything else, using further calls to the api, if necessary.
        unless skip_info?
          %w(first_name last_name phone skype avatar_hash real_name real_name_normalized).each do |key|
            hash[key.to_sym] = (
              user_info['user'].to_h['profile'] ||
              user_profile['profile']
            ).to_h[key]
          end

          %w(deleted status color tz tz_label tz_offset is_admin is_owner is_primary_owner is_restricted is_ultra_restricted is_bot has_2fa).each do |key|
            hash[key.to_sym] = user_info['user'].to_h[key]
          end

          more_info = {
            image: (
              hash[:image] ||
              user_identity.to_h['image_48'] ||
              user_info['user'].to_h['profile'].to_h['image_48'] ||
              user_profile['profile'].to_h['image_48']
              ),
            name:(
              hash[:name] ||
              user_identity['name'] ||
              user_info['user'].to_h['real_name'] ||
              user_profile['profile'].to_h['real_name']
              ),
            email:(
              hash[:email] ||
              user_identity.to_h['email'] ||
              user_info['user'].to_h['profile'].to_h['email'] ||
              user_profile['profile'].to_h['email']
              ),
            team_name:(
              hash[:team_name] ||
              team_identity.to_h['name'] ||
              team_info['team'].to_h['name']
              ),
            team_domain:(
              auth['team'].to_h['domain'] ||
              team_identity.to_h['domain'] ||
              team_info['team'].to_h['domain']
              ),
            team_image:(
              auth['team'].to_h['image_44'] ||
              team_identity.to_h['image_44'] ||
              team_info['team'].to_h['icon'].to_h['image_44']
              ),
            team_email_domain:(
              team_info['team'].to_h['email_domain']
              ),
            nickname:(
              user_info.to_h['user'].to_h['name'] ||
              auth['user'].to_h['name'] ||
              user_identity.to_h['name']
              ),
          }
          
          hash.merge!(more_info)
        end
        hash
      end

      extra do
        {
          web_hook_info: web_hook_info,
          #bot_info: bot_info,
          bot_info: auth['bot'] || bot_info['bot'],
          auth: auth,
          identity: identity,
          user_info: user_info,
          user_profile: user_profile,
          team_info: team_info,
          apps_permissions_users_list: apps_permissions_users_list,
          scopes_requested: env['omniauth.strategy'] && env['omniauth.strategy'].options && env['omniauth.strategy'].options.scope,
          raw_info: {
            auth: access_token.dup.tap{|i| i.remove_instance_variable(:@client)},
            identity: @identity_raw,
            user_info: @user_info_raw,
            user_profile: @user_profile_raw,
            team_info: @team_info_raw,
            bot_info: @bot_info_raw,
            apps_permissions_users_list_raw: @apps_permissions_users_list_raw
          }
        }
      end
      
      # Sets team subdomain from :team_domain in the provider block,
      # or at runtime from params['team_domain'] in the omniauth authorization url.
      # In contrast to setting :team, setting :team_domain will force authentication
      # against the specified team. However, if you are already logged in to that team,
      # specifying the :team_domain will not let you skip the Slack OAUTH dialog,
      # as happens when you specify :team.
      #
      # Using :team_domain, you get
      #   https://myotherteam.slack.com/oauth/authorize&scope=...
      #
      # Using :team, you get 
      #   https://slack.com/oauth/authorize?team=myotherteam&scope=...
      # 
      # Specify both :team and :team_domain to get the user through the OAUTH
      # process as quickly as possible (assuming your user already has a token
      # with the necessary scopes, and you know what team they are authenticating against).
      #
      # Note that this behavior is entirely controlled by Slack. The omniauth-slack gem
      # only passes data to Slack and has no say in how the Slack OAUTH process works.
      #
      # def client
      #   puts "Requesting client"
      #   super.tap do |c|
      #     team_domain = request.params['team_domain'] || authorize_params[:team_domain]
      #     #c.site = "https://#{team_domain}.slack.com" if !team_domain.to_s.empty?
      #     c.site = "http://localhost:9292"
      #   end
      # end
      
      
      # TODO: Is there a better way to do this?
      # This might be the best way... see https://github.com/omniauth/omniauth/issues/390
      def authorize_params
        #puts "Requesting authorize_params"
        super.tap do |params|
          %w[scope team].each do |v|
            if !request.params[v].to_s.empty?
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end

      # TODO: Find out why this is here and how it works.
      # Ok... see here https://github.com/omniauth/omniauth/blob/master/lib/omniauth/strategy.rb
      # This override cuts out the query_string... why?
      # def callback_url
      #   puts "Requesting callback_url"
      #   puts "full_host: #{full_host}"
      #   puts "script_name: #{script_name}"
      #   puts "callback_path: #{callback_path}"
      #   full_host + script_name + callback_path
      # end
      
      
      private
      
      # Preload additional api calls with limited thread pool.
      def preload_data_with_threads(num_threads=options.preload_data_with_threads.to_i)
        #puts "Calling preload_data_with_threads"
        log :info, "Calling preload_data_with_threads(#{num_threads})."
        work_q = Queue.new
        %w(apps_permissions_users_list identity user_info user_profile team_info bot_info).each{|x| work_q.push x }
        workers = (0...(num_threads)).map do
          Thread.new do
            begin
              while x = work_q.pop(true)
                send x
              end
            rescue ThreadError
            end
          end
        end; "ok"
        workers.map(&:join); "ok"
      end
      
      # Parsed data returned from /slack/oauth.access api call.
      def auth
        @auth ||= access_token.params.to_h.merge({'token' => access_token.token})
      end

      def identity
        #puts "Requesting identity"
        return {} unless has_scope?(identity: ['identity.basic','identity:read:user'])
        @identity_raw ||= access_token.get('/api/users.identity', headers: {'X-Slack-User' => user_id})
        @identity ||= @identity_raw.parsed
      end

      def user_identity
        @user_identity ||= identity['user'].to_h
      end

      def team_identity
        @team_identity ||= identity['team'].to_h
      end

      def user_info
        #puts "Requesting user_info"
        return {} unless has_scope?(identity: 'users:read', team: 'users:read')
        @user_info_raw ||= access_token.get('/api/users.info', params: {user: user_id}, headers: {'X-Slack-User' => user_id})
        @user_info ||= @user_info_raw.parsed
      end
      
      def user_profile
        #puts "Requesting user_profile"
        return {} unless has_scope?(identity: 'users.profile:read', team: 'users.profile:read')
        @user_profile_raw ||= access_token.get('/api/users.profile.get', params: {user: user_id}, headers: {'X-Slack-User' => user_id})
        @user_profile ||= @user_profile_raw.parsed
      end

      def team_info
        #puts "Requesting team_info"
        return {} unless has_scope?(identity: 'team:read', team: 'team:read')
        @team_info_raw ||= access_token.get('/api/team.info')
        @team_info ||= @team_info_raw.parsed
      end

      def web_hook_info
        return {} unless access_token.params.key? 'incoming_webhook'
        #access_token.params['incoming_webhook']
        auth['incoming_webhook']
      end
      
      def bot_info
        #puts "Requesting bot_info"
        return {} unless has_scope?(identity: 'users:read')
        @bot_info_raw ||= access_token.get('/api/bots.info')
        @bot_info ||= @bot_info_raw.parsed
      end
      
      def user_id
        auth['user_id'] || auth['user'].to_h['id'] || auth['authorizing_user'].to_h['user_id']
      end
      
      def team_id
        auth['team_id'] || auth['team'].to_h['id']
      end
      
      # Api all to get user permissions for workspace token.
      # This is needed because workspace token 'sign-in-with-slack' is missing scopes
      # in the :scope field.
      #
      # Returns [<id>: <resource>]
      def apps_permissions_users_list
        #puts "Requesting apps_permissions_users_list"
        return {} unless is_app_token
        @apps_permissions_users_list_raw ||= access_token.get('/api/apps.permissions.users.list')
        @apps_permissions_users_list ||= @apps_permissions_users_list_raw.parsed['resources'].inject({}){|h,i| h[i['id']] = i; h}
      end
      
      def is_app_token
        auth['token_type'].to_s == 'app'
      end
      
      # Scopes come from at least 3 different places now.
      # * The classic :scope field (string)
      # * New workshop token :scopes field (hash)
      # * Separate call to apps.permissions.users.list (array)
      #
      # This returns hash of workspace scopes, with classic & new identity scopes in :identity.
      # Lists of scopes are in array form.
      def all_scopes
        @all_scopes ||=
        {'identity' => (auth['scope'] || apps_permissions_users_list[user_id].to_h['scopes'].join(',')).to_s.split(',')}
        .merge(auth['scopes'].to_h)
        #.merge(access_token['scopes'].to_h)
      end
      
      # Determine if given scopes exist in current authorization.
      # Scopes is hash where
      #   key == scope type <identity|app_hope|team|channel|group|mpim|im>
      #   val == array or string of individual scopes.
      def has_scope?(**scopes_hash)
        scopes_hash.detect do |section, scopes|
          test_scopes = case
            when scopes.is_a?(String); scopes.split(',')
            when scopes.is_a?(Array); scopes
            else raise "Scope must be a string or array"
          end
          test_scopes.detect do |scope|
            all_scopes[section.to_s].to_a.include?(scope.to_s)
          end
        end
      end
      
    end
  end
end

