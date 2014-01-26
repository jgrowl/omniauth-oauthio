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

      #attr_accessor :access_token

      def client_with_provider(provider)
        options.client_options.merge!({authorize_url: "#{options.client_options.authorization_url}/#{provider}"})
        client
      end

      def callback_url
        full_host + script_name + callback_path
      end


      #def authorize_params
      #  options.authorize_params[:state] = SecureRandom.hex(24)
      #  params = options.authorize_params.merge(options.authorize_options.inject({}){|h,k| h[k.to_sym] = options[k] if options[k]; h})
      #  if OmniAuth.config.test_mode
      #    @env ||= {}
      #    @env['rack.session'] ||= {}
      #  end
      #  session['omniauth.state'] = params[:state]
      #  params
      #end
      #
      #def token_params
      #  options.token_params.merge(options.token_options.inject({}){|h,k| h[k.to_sym] = options[k] if options[k]; h})
      #end

      # NOTE: I don't completely know how to handle the request_phase at the moment. The OAuth.io response from making
      # an auth request return data using an # tag in the redirect url. This is fine when I want javascript to pick
      # up the incoming data, but not if I don't want to use OAuth.io's popup functionality. I need to investigate
      # any options that can be passed to the /auth service to change the result or maybe do something to trigger
      # the callback phase and automatically post the data.
      def request_phase
        params = authorize_params
        provider = params[:provider]
        params = params.except(:provider)

        redirect_url = client_with_provider(provider).auth_code.authorize_url({:redirect_uri => callback_url}.merge(params))
        redirect redirect_url
      end

      def auth_hash
        # Use the actual provider instead of oauthio!
        provider = access_token.params.provider
        class_name =
        provider_info = "Oauthio::#{provider.classify}".constantize.new(access_token, client.secret, options)
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
        #if !options.provider_ignores_state && (request.params['state'].to_s.empty? || request.params['state'] != session.delete('omniauth.state'))
        #  raise CallbackError.new(nil, :csrf_detected)
        #end
        #
        self.access_token = build_access_token
        self.access_token = access_token.refresh! if access_token.expired?

        env['omniauth.auth'] = auth_hash
        call_app!

      #rescue ::Oauthio::Error, CallbackError => e
      #  fail!(:invalid_credentials, e)
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
        ::Oauthio::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
      end

      # TODO: Remove this if I can access this from OAuth strat
      #def deep_symbolize(hash)
      #  hash.inject({}) do |h, (k,v)|
      #    h[k.to_sym] = v.is_a?(Hash) ? deep_symbolize(v) : v
      #    h
      #  end
      #end


      def build_access_token
        params = env['action_dispatch.request.request_parameters']
        verifier = params[:code]
        client.auth_code.get_token(verifier, token_params.to_hash(:symbolize_keys => true))
      end
      #
      ## An error that is indicated in the OAuth 2.0 callback.
      ## This could be a `redirect_uri_mismatch` or other
      #class CallbackError < StandardError
      #  attr_accessor :error, :error_reason, :error_uri
      #
      #  def initialize(error, error_reason=nil, error_uri=nil)
      #    self.error = error
      #    self.error_reason = error_reason
      #    self.error_uri = error_uri
      #  end
      #end
    end
  end
end




