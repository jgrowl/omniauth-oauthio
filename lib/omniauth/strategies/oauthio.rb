require 'omniauth/strategies/oauth2'
require 'base64'
require 'openssl'
require 'rack/utils'
require 'uri'


module Oauthio
  module Strategy
    # The Authorization Code Strategy
    #
    # @see http://tools.ietf.org/html/draft-ietf-oauth-v2-15#section-4.1
    class OauthioAuthCode < OAuth2::Strategy::AuthCode
      # The required query parameters for the authorize URL
      #
      # @param [Hash] params additional query parameters
      def authorize_params(params={})
        params.merge('response_type' => 'code', 'k' => @client.id)
      end
    end
  end
end

module Oauthio
  # The OAuth2::Client class
  class Client < OAuth2::Client
    def auth_code
      @auth_code ||= Oauthio::Strategy::OauthioAuthCode.new(self)
    end
  end
end

module OmniAuth
  module Strategies
    class Oauthio < OmniAuth::Strategies::OAuth2

      # Give your strategy a name.
      option :name, "oauthio"

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, {
          :site => 'https://oauth.io',
          :authorize_url => 'https://oauth.io/auth',
          #:token_url => '/oauth/access_token'
      }

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid{ raw_info['id'] }

      info do
        {
            :name => raw_info['name'],
            :email => raw_info['email']
        }
      end

      extra do
        {
            'raw_info' => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get('/me').parsed
      end

      def client
        ::Oauthio::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
      end

      def client_with_provider(provider)
        options.client_options.merge!({authorize_url: "/auth/#{provider}"})
        client
      end

      def request_phase
        params = authorize_params
        provider = params[:provider]
        params = params.except(:provider)

        redirect_url = client_with_provider(provider).auth_code.authorize_url({:redirect_uri => callback_url}.merge(params))
        redirect redirect_url
      end

      # The setup phase looks for the `:setup` option to exist and,
      # if it is, will call either the Rack endpoint supplied to the
      # `:setup` option or it will call out to the setup path of the
      # underlying application. This will default to `/auth/:provider/setup`.
      def setup_phase
        if options[:setup].respond_to?(:call)
          log :info, 'Setup endpoint detected, running now.'
          options[:setup].call(env)
        elsif options.setup?
          log :info, 'Calling through to underlying application for setup.'
          setup_env = env.merge('PATH_INFO' => setup_path, 'REQUEST_METHOD' => 'GET')
          call_app!(setup_env)
        end
      end

      def authorize_params
        super.tap do |params|
          %w[display scope auth_type provider].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end

          params[:scope]
        end
      end




      #class NoAuthorizationCodeError < StandardError; end
      #class UnknownSignatureAlgorithmError < NotImplementedError; end
      #
      #option :token_params, {
      #  :parse => :query
      #}
      #
      #option :access_token_options, {
      #  :header_format => 'OAuth %s',
      #  :param_name => 'access_token'
      #}
      #
      #option :authorize_options, [:scope, :display, :auth_type]
      #
      #uid { raw_info['id'] }
      #
      #info do
      #  prune!({
      #    'nickname' => raw_info['username'],
      #    'email' => raw_info['email'],
      #    'name' => raw_info['name'],
      #    'first_name' => raw_info['first_name'],
      #    'last_name' => raw_info['last_name'],
      #    'image' => image_url(uid, options),
      #    'description' => raw_info['bio'],
      #    'urls' => {
      #      'Facebook' => raw_info['link'],
      #      'Website' => raw_info['website']
      #    },
      #    'location' => (raw_info['location'] || {})['name'],
      #    'verified' => raw_info['verified']
      #  })
      #end
      #
      #extra do
      #  hash = {}
      #  hash['raw_info'] = raw_info unless skip_info?
      #  prune! hash
      #end
      #
      #def raw_info
      #  @raw_info ||= access_token.get('/me', info_options).parsed || {}
      #end
      #
      #def info_options
      #  params = {:appsecret_proof => appsecret_proof}
      #  params.merge!({:fields => options[:info_fields]}) if options[:info_fields]
      #  params.merge!({:locale => options[:locale]}) if options[:locale]
      #
      #  { :params => params }
      #end
      #
      #def callback_phase
      #  super
      #rescue NoAuthorizationCodeError => e
      #  fail!(:no_authorization_code, e)
      #rescue UnknownSignatureAlgorithmError => e
      #  fail!(:unknown_signature_algoruthm, e)
      #end
      #
      #def request_phase
      #  if signed_request_contains_access_token?
      #    # If we already have an access token, we can just hit the callback URL directly and pass the signed request.
      #    params = { :signed_request => raw_signed_request }
      #    query = Rack::Utils.build_query(params)
      #
      #    url = callback_url
      #    url << "?" unless url.match(/\?/)
      #    url << "&" unless url.match(/[\&\?]$/)
      #    url << query
      #
      #    redirect url
      #  else
      #    super
      #  end
      #end
      #
      ## NOTE If we're using code from the signed request then FB sets the redirect_uri to '' during the authorize
      ##      phase and it must match during the access_token phase:
      ##      https://github.com/facebook/php-sdk/blob/master/src/base_facebook.php#L348
      #def callback_url
      #  if @authorization_code_from_signed_request
      #    ''
      #  else
      #    options[:callback_url] || super
      #  end
      #end
      #
      #def access_token_options
      #  options.access_token_options.inject({}) { |h,(k,v)| h[k.to_sym] = v; h }
      #end
      #
      ## You can pass +display+, +scope+, or +auth_type+ params to the auth request, if you need to set them dynamically.
      ## You can also set these options in the OmniAuth config :authorize_params option.
      ##
      ## /auth/facebook?display=popup
      #def authorize_params
      #  super.tap do |params|
      #    %w[display scope auth_type].each do |v|
      #      if request.params[v]
      #        params[v.to_sym] = request.params[v]
      #      end
      #    end
      #
      #    params[:scope] ||= DEFAULT_SCOPE
      #  end
      #end
      #
      ## Parse signed request in order, from:
      ##
      ## 1. The request 'signed_request' param (server-side flow from canvas pages) or
      ## 2. A cookie (client-side flow via JS SDK)
      #def signed_request
      #  @signed_request ||= raw_signed_request && parse_signed_request(raw_signed_request)
      #end
      #
      #protected
      #
      #def build_access_token
      #  if signed_request_contains_access_token?
      #    hash = signed_request.clone
      #    ::OAuth2::AccessToken.new(
      #      client,
      #      hash.delete('oauth_token'),
      #      hash.merge!(access_token_options.merge(:expires_at => hash.delete('expires')))
      #    )
      #  else
      #    with_authorization_code! { super }.tap do |token|
      #      token.options.merge!(access_token_options)
      #    end
      #  end
      #end
      #
      #private
      #
      #def raw_signed_request
      #  request.params['signed_request'] || request.cookies["fbsr_#{client.id}"]
      #end
      #
      ## If the signed_request comes from a FB canvas page and the user has already authorized your application, the JSON
      ## object will be contain the access token.
      ##
      ## https://developers.facebook.com/docs/authentication/canvas/
      #def signed_request_contains_access_token?
      #  signed_request && signed_request['oauth_token']
      #end
      #
      ## Picks the authorization code in order, from:
      ##
      ## 1. The request 'code' param (manual callback from standard server-side flow)
      ## 2. A signed request (see #signed_request for more)
      #def with_authorization_code!
      #  if request.params.key?('code')
      #    yield
      #  elsif code_from_signed_request = signed_request && signed_request['code']
      #    request.params['code'] = code_from_signed_request
      #    @authorization_code_from_signed_request = true
      #    begin
      #      yield
      #    ensure
      #      request.params.delete('code')
      #      @authorization_code_from_signed_request = false
      #    end
      #  else
      #    raise NoAuthorizationCodeError, 'must pass either a `code` parameter or a signed request (via `signed_request` parameter or a `fbsr_XXX` cookie)'
      #  end
      #end
      #
      #def prune!(hash)
      #  hash.delete_if do |_, value|
      #    prune!(value) if value.is_a?(Hash)
      #    value.nil? || (value.respond_to?(:empty?) && value.empty?)
      #  end
      #end
      #
      #def parse_signed_request(value)
      #  signature, encoded_payload = value.split('.')
      #  return if signature.nil?
      #
      #  decoded_hex_signature = base64_decode_url(signature)
      #  decoded_payload = MultiJson.decode(base64_decode_url(encoded_payload))
      #
      #  unless decoded_payload['algorithm'] == 'HMAC-SHA256'
      #    raise UnknownSignatureAlgorithmError, "unknown algorithm: #{decoded_payload['algorithm']}"
      #  end
      #
      #  if valid_signature?(client.secret, decoded_hex_signature, encoded_payload)
      #    decoded_payload
      #  end
      #end
      #
      #def valid_signature?(secret, signature, payload, algorithm = OpenSSL::Digest::SHA256.new)
      #  OpenSSL::HMAC.digest(algorithm, secret, payload) == signature
      #end
      #
      #def base64_decode_url(value)
      #  value += '=' * (4 - value.size.modulo(4))
      #  Base64.decode64(value.tr('-_', '+/'))
      #end
      #
      #def image_url(uid, options)
      #  uri_class = options[:secure_image_url] ? URI::HTTPS : URI::HTTP
      #  url = uri_class.build({:host => 'graph.facebook.com', :path => "/#{uid}/picture"})
      #
      #  query = if options[:image_size].is_a?(String)
      #    { :type => options[:image_size] }
      #  elsif options[:image_size].is_a?(Hash)
      #    options[:image_size]
      #  end
      #  url.query = Rack::Utils.build_query(query) if query
      #
      #  url.to_s
      #end
      #
      #def appsecret_proof
      #  @appsecret_proof ||= OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, client.secret, access_token.token)
      #end
    end
  end
end
