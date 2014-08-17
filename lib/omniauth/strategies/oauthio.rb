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
      option :name, 'oauthio'

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, {:site => 'https://oauth.io'}

      option :client_id, nil
      option :client_secret, nil

      def current_path
        # This might not be completely safe. I want to ensure that the
        # current_path does not have a format at the end so the .json should be
        # removed.
        super.sub(/(\.json)$/, '')
      end

      def sub_provider
        # e.g., /auth/oauthio/twitter
        after_base = request.path.split("#{path_prefix}/#{name}/").last
        slashes = after_base.split('/')
        str = slashes.length > 1 ? slashes.first : after_base
        str.split('.').first
      end

      def request_path
        if (path=options[:request_path]).is_a?(String)
          path
        else
          "#{path_prefix}/#{name}/#{sub_provider}"
        end
      end

      def callback_path
        callback = options[:callback_path]
        path = callback if callback.is_a?(String)
        if callback.respond_to?(:call) && callback.call(env)
          path ||= current_path
        end
        path ||= custom_path(:request_path)
        path ||= "#{path_prefix}/#{name}/#{sub_provider}/callback"
        path
      end

      def request_phase
        params = authorize_params
        provider = sub_provider

        opts = {:state => params.state}.to_json

        # We may want to skip redirecting the user if calling from a
        # single-page application that does not want to reload the page.
        if request.path_info =~ /\.json$/
          return Rack::Response.new(opts, 200,
                                    'content-type' => 'application/json').finish
        end

        defaults = {:redirect_uri => callback_url_with_state(params.state)}
        options = defaults.merge({opts: opts})
        redirect client.auth_code.authorize_url(provider, options)
      end

      def callback_url_with_state(state)
        uri = URI.parse(callback_url)
        new_query_ar = URI.decode_www_form(uri.query || '') << ['state', state]
        uri.query = URI.encode_www_form(new_query_ar)
        uri.to_s
      end

      def auth_hash
        provider_info = ::Oauthio::Providers::Oauthio.new(access_token,
                                                          client.secret,
                                                          options)
        provider = access_token.provider
        hash = AuthHash.new(:provider => provider, :uid => provider_info.uid)
        hash.info = provider_info.info unless provider_info.skip_info?
        if provider_info.credentials
          hash.credentials = provider_info.credentials
        end
        hash.extra = provider_info.extra if provider_info.extra
        hash
      end

      def callback_phase
        unless request.params['code']
          # TODO: Is there an option we can pass to OAuth.io to prevent it from
          # putting the code in the hash part of the url? Currently we have to
          # parse the hash to get the code and then do an additional redirect.
          html = <<-END.gsub(/^\s{10}/, '')
          <!DOCTYPE html>
          <html>
          <head>
            <script>
            (function() {
              "use strict";
              var hash = document.location.hash;
              var data = JSON.parse(decodeURIComponent(hash.split("=")[1]));
              var code = data.data.code;
              document.location.href = document.location.origin + document.location.pathname + document.location.search + "&code=" + code;
            })();
            </script>
          </head>
          <body></body>
          </html>
          END
          return Rack::Response.new(html, 200).finish
        end

        error_message = request.params['error_reason'] ||
                        request.params['error']
        if error_message
          error_description = request.params['error_description'] ||
                              request.params['error_reason']
          error = CallbackError.new(request.params['error'],
                                    error_description,
                                    request.params['error_uri'])
          fail!(error_message, error)
        elsif !options.provider_ignores_state && !verified_state?
          error = CallbackError.new(:csrf_detected, 'CSRF detected')
          fail!(:csrf_detected, error)
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
        ::Oauthio::Client.new(options.client_id, options.client_secret,
                              deep_symbolize(options.client_options))
      end

      def verified_state?
        state = request.params['state']
        return false if state.to_s.empty?
        state == session['omniauth.state']
      end
    end
  end
end

