require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    
    class Slack < OmniAuth::Strategies::OAuth2
      option :name, 'slack'

      option :authorize_options, [:scope, :team, :team_domain]

      option :client_options, {
        site: 'https://slack.com',
        token_url: '/api/oauth.access'
      }

      # Add team_domain to site subdomain if provided in auth url or provider options. 
      option :setup, lambda{|env|
        strategy = env['omniauth.strategy']
        team_domain = strategy.request.params['team_domain'] || strategy.options[:team_domain]
        site = strategy.options[:client_options]['site']
        strategy.options[:client_options].site = (
          !team_domain.to_s.empty? ? site.sub(/\:\\\\/, "://#{team_domain}.") : site
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
      
      # Pass on certain authorize_params to the Slack authorization GET request.
      # See https://github.com/omniauth/omniauth/issues/390
      def authorize_params
        super.tap do |params|
          %w[scope team].each do |v|
            if !request.params[v].to_s.empty?
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end

      
      private
      
      # Preload additional api calls with a pool of threads.
      def preload_data_with_threads(num_threads=options.preload_data_with_threads.to_i)
        log :debug, "Calling preload_data_with_threads(#{num_threads})."
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
        return {} unless has_scope?(identity: 'users:read', team: 'users:read')
        @user_info_raw ||= access_token.get('/api/users.info', params: {user: user_id}, headers: {'X-Slack-User' => user_id})
        @user_info ||= @user_info_raw.parsed
      end
      
      def user_profile
        return {} unless has_scope?(identity: 'users.profile:read', team: 'users.profile:read')
        @user_profile_raw ||= access_token.get('/api/users.profile.get', params: {user: user_id}, headers: {'X-Slack-User' => user_id})
        @user_profile ||= @user_profile_raw.parsed
      end

      def team_info
        return {} unless has_scope?(identity: 'team:read', team: 'team:read')
        @team_info_raw ||= access_token.get('/api/team.info')
        @team_info ||= @team_info_raw.parsed
      end

      def web_hook_info
        return {} unless auth.key? 'incoming_webhook'
        auth['incoming_webhook']
      end
      
      def bot_info
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
      
      # API call to get user permissions for workspace token.
      # This is needed because workspace token 'sign-in-with-slack' is missing scopes
      # in the :scope field (acknowledged issue in developer preview).
      #
      # Returns [<id>: <resource>]
      def apps_permissions_users_list
        return {} unless is_app_token
        @apps_permissions_users_list_raw ||= access_token.get('/api/apps.permissions.users.list')
        @apps_permissions_users_list ||= @apps_permissions_users_list_raw.parsed['resources'].inject({}){|h,i| h[i['id']] = i; h}
      end
      
      # Is this a workspace app token?
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

