require 'omniauth/strategies/oauth2'
require 'base64'
require 'openssl'
require 'rack/utils'
require 'uri'

module OmniAuth
  module Strategies
    class Oauthio < OmniAuth::Strategies::OAuth2
      include OmniAuth::Strategy

      args [:client_id, :client_secret]

      # Give your strategy a name.
      option :name, "oauthio"

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, {
          :site => 'https://oauth.io',
      }

      option :client_id, nil
      option :client_secret, nil

      # Returns true if the environment recognizes either the
      # request or callback path.
      def on_auth_path?
        on_request_path? || on_callback_path?
      end

      def client_with_provider(provider)
        options.client_options.merge!({authorize_url: "#{options.client_options.authorization_url}/#{provider}"})
        client
      end

      def current_path
        # This might not be completely safe. I want to ensure that the current_path does not have a format at the end
        # so the .json should be removed.
        super.split('.').first
      end

      def on_request_path?
        if options.request_path.respond_to?(:call)
          options.request_path.call(env)
        else
          on_path?(request_path)
        end
      end

      def on_path?(path)
        current_path.casecmp(path) == 0
      end

      def on_callback_path?
        on_path?(callback_path)
      end

      def sub_provider
        test = request.path.split("#{path_prefix}/#{name}/").last
        slashes = test.split('/')
        if slashes.length > 1
          # return ''
          return slashes.first.split('.').first
        end

        test.split('.').first
      end

      def request_path
        options[:request_path].is_a?(String) ? options[:request_path] : "#{path_prefix}/#{name}/#{sub_provider}"
      end

      def callback_path
        path = options[:callback_path] if options[:callback_path].is_a?(String)
        path ||= current_path if options[:callback_path].respond_to?(:call) && options[:callback_path].call(env)
        path ||= custom_path(:request_path)
        path ||= "#{path_prefix}/#{name}/#{sub_provider}/callback"
        path
      end

      def path_prefix
        options[:path_prefix] || OmniAuth.config.path_prefix
      end

      def request_phase
        params = authorize_params
        # We may want to skip redirecting the user if calling from a SPA that does not want to reload the page.
        # The json option will return a json response instead of redirecting.
        if request.path_info.include?('.json')
          json = {state: session['omniauth.state']}.to_json
          return Rack::Response.new(json, 200, 'content-type' => 'application/json').finish
        end

        # TODO: Check the redirect url. I think it may be hitting the wrong url.
        provider = params[:provider]
        params = params.except(:provider)
        redirect_url = client_with_provider(provider).auth_code.authorize_url({:redirect_uri => callback_url}.merge(params))
        redirect redirect_url
      end

      def auth_hash
        class_constant = "Oauthio::Providers::Oauthio".constantize
        provider_info = class_constant.new(access_token, client.secret, options)
        # TODO: We don't need to be fancy about this since we only have one real provider right?
        # provider_info = Oauthio::Providers::Oauthio.new(access_token, client.secret, options)
        provider = access_token.provider
        hash = AuthHash.new(:provider => provider, :uid => provider_info.uid)
        hash.info = provider_info.info unless provider_info.skip_info?
        hash.credentials = provider_info.credentials if provider_info.credentials
        hash.extra = provider_info.extra if provider_info.extra
        hash
      end

      def callback_phase
        #if request.params['error'] || request.params['error_reason']
        #  raise CallbackError.new(request.params['error'], request.params['error_description'] || request.params['error_reason'], request.params['error_uri'])
        #end
        if !options.provider_ignores_state && !verified_state?
          raise CallbackError.new(nil, :csrf_detected)
        end

        self.access_token = build_access_token
        self.access_token = access_token.refresh! if access_token.expired?

        env['omniauth.auth'] = auth_hash
        # Delete the omniauth.state after we have verified all requests
        session.delete('omniauth.state')
        call_app!

      #rescue ::Oauthio::Error, CallbackError => e
      rescue CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::MultiJson::DecodeError => e
        fail!(:invalid_response, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      protected
      # Client should only be access via client_with_provider
      def client
        state = session['omniauth.state']
        options.client_options[:state] = state
        ::Oauthio::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
      end

      def verified_state?
        # state = authorize_params['state']
        state = request.params['state']
        return false if state.to_s.empty?
        state == session['omniauth.state']
      end
    end
  end
end




