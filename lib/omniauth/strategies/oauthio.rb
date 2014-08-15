require 'omniauth/strategies/oauth2'
require 'base64'
require 'openssl'
require 'rack/utils'
require 'uri'
require 'json'

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

      def current_path
        # This might not be completely safe. I want to ensure that the current_path does not have a format at the end
        # so the .json should be removed.
        super.sub(/(\.json)$/, '');
      end

      def sub_provider
        after_base = request.path.split("#{path_prefix}/#{name}/").last
        slashes = after_base.split('/')
        slashes.length > 1 ? slashes.first.split('.').first : after_base.split('.').first
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

      def request_phase
        params = authorize_params
        provider = sub_provider

        opts = {
            state: params.state
        }.to_json

        # We may want to skip redirecting the user if calling from a SPA that does not want to reload the page.
        if request.path_info =~ /\.json$/
          return Rack::Response.new(opts, 200, 'content-type' => 'application/json').finish
        end

        redirect client.auth_code.authorize_url(provider, {:redirect_uri => callback_url_with_state(params.state)}.merge({opts: opts}))
      end


      # note: the callback phase should be the same regardless!
      #
      # The request phase though needs to have multiple options
      # 1. take care of everything the js-sdk does.
      # 2. partial control where we can get the state to pass to the js-sdk.

      def callback_url_with_state(state)
        uri = URI.parse(callback_url)
        new_query_ar = URI.decode_www_form(uri.query || '') << ['state', state]
        uri.query = URI.encode_www_form(new_query_ar)
        uri.to_s
      end

      def auth_hash
        provider_info = ::Oauthio::Providers::Oauthio.new(access_token, client.secret, options)
        provider = access_token.provider
        hash = AuthHash.new(:provider => provider, :uid => provider_info.uid)
        hash.info = provider_info.info unless provider_info.skip_info?
        hash.credentials = provider_info.credentials if provider_info.credentials
        hash.extra = provider_info.extra if provider_info.extra
        hash
      end

      def callback_phase
        if !request.params['code']
          # TODO: Is there an option we can pass to OAuth.io to prevent it from putting the code in the hash part of the url?
          # Currently we to parse the hash to get the code and then do an additional redirect.
          html = '<!DOCTYPE html>
                    <html><head><script>(function() {
            "use strict";
            var hash = document.location.hash;
            var data = JSON.parse(decodeURIComponent(hash.split("=")[1]));
            var code = data.data.code
            document.location.href = document.location.origin + document.location.pathname + document.location.search + "&code=" + code
            //document.location.href = document.location.href + "&code=" + code
          })();</script></head><body></body></html>'
          return Rack::Response.new(html, 200).finish
        end

        error = request.params['error_reason'] || request.params['error']
        if error
          fail!(error, CallbackError.new(request.params['error'], request.params['error_description'] || request.params['error_reason'], request.params['error_uri']))
        elsif !options.provider_ignores_state && !verified_state?
          fail!(:csrf_detected, CallbackError.new(:csrf_detected, 'CSRF detected'))
        else
          self.access_token = build_access_token
          self.access_token = access_token.refresh! if access_token.expired?

          env['omniauth.auth'] = auth_hash
          # Delete the omniauth.state after we have verified all requests
          session.delete('omniauth.state')
          call_app!
        end
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
      def client
        state = session['omniauth.state']
        options.client_options[:state] = state
        ::Oauthio::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
      end

      def verified_state?
        state = request.params['state']
        return false if state.to_s.empty?
        state == session['omniauth.state']
      end
    end
  end
end

