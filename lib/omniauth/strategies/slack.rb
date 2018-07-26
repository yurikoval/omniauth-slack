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

      option :auth_token_params, {
        mode: :query,
        param_name: 'token'
      }
      
      option :preload_data_with_threads, 0

      # User ID is not guaranteed to be globally unique across all Slack users.
      # The combination of user ID and team ID, on the other hand, is guaranteed
      # to be globally unique.
      uid { "#{auth['user_id'] || auth['user'].to_h['id']}-#{auth['team_id'] || auth['team'].to_h['id']}" }

      info do
        
        # Experimental Thread Pool
        if options.preload_data_with_threads.to_i > 0
          work_q = Queue.new
          %w(identity user_info user_profile team_info bot_info).each{|x| work_q.push x }
          workers = (0...(options.preload_data_with_threads.to_i)).map do
            Thread.new do
              #puts "New thread #{Thread.current}"
              begin
                while x = work_q.pop(true)
                  #puts "Processing '#{x}' with thread #{Thread.current}"
                  send x
                end
              rescue ThreadError
              end
            end
          end; "ok"
          workers.map(&:join); "ok"
        end
        
      
        # Start with only what we can glean from the authorization response.
        hash = { 
          name: auth['user'].to_h['name'],
          email: auth['user'].to_h['email'],
          user_id: auth['user_id'] || auth['user'].to_h['id'],
          team_name: auth['team_name'] || auth['team'].to_h['name'],
          team_id: auth['team_id'] || auth['team'].to_h['id'],
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
          identity: @identity,
          user_info: @user_info,
          user_profile: @user_profile,
          team_info: @team_info,
          raw_info: {
            auth: access_token.dup.tap{|i| i.remove_instance_variable(:@client)},
            identity: @identity_raw,
            user_info: @user_info_raw,
            user_profile: @user_profile_raw,
            team_info: @team_info_raw,
            bot_info: @bot_info_raw
          }
        }
      end
      
      credentials do
        {
          token: access_token.token,
          scope: access_token['scope'],
          expires: false
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
      def client
        super.tap do |c|
          team_domain = request.params['team_domain'] || authorize_params[:team_domain]
          c.site = "https://#{team_domain}.slack.com" if !team_domain.to_s.empty?
        end
      end
      
      def authorize_params
        super.tap do |params|
          %w[scope team].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end
      
      def auth
        access_token.params.to_h.merge({token: access_token.token})
      end

      def identity
        return {} unless has_scope?('identity.basic')
        @identity_raw ||= access_token.get('/api/users.identity')
        @identity ||= @identity_raw.parsed
      end

      def user_identity
        @user_identity ||= identity['user'].to_h
      end

      def team_identity
        @team_identity ||= identity['team'].to_h
      end

      def user_info
        return {} unless has_scope?('users:read')
        url = URI.parse('/api/users.info')
        url.query = Rack::Utils.build_query(user: auth['user_id'] || auth['user'].to_h['id'])
        url = url.to_s

        @user_info_raw ||= access_token.get(url)
        @user_info ||= @user_info_raw.parsed
      end
      
      def user_profile
        return {} unless has_scope?('users.profile:read')
        url = URI.parse('/api/users.profile.get')
        url.query = Rack::Utils.build_query(user: auth['user_id'] || auth['user'].to_h['id'])
        url = url.to_s

        @user_profile_raw ||= access_token.get(url)
        @user_profile ||= @user_profile_raw.parsed
      end

      def team_info
        return {} unless has_scope?('team:read')
        @team_info_raw ||= access_token.get('/api/team.info')
        @team_info ||= @team_info_raw.parsed
      end

      def web_hook_info
        return {} unless access_token.params.key? 'incoming_webhook'
        access_token.params['incoming_webhook']
      end
      
      def bot_info
        return {} unless has_scope?('users:read')
        @bot_info_raw ||= access_token.get('/api/bots.info')
        @bot_info ||= @bot_info_raw.parsed
      end


      private

      def callback_url
        full_host + script_name + callback_path
      end
      
      def has_scope?(scope)
        access_token['scope'].to_s.split(',').include?(scope.to_s)
      end
      
    end
  end
end