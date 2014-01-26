require 'omniauth/strategies/oauth2'
require 'base64'
require 'openssl'
require 'rack/utils'
require 'uri'

module Oauthio
    class Facebook
      def initialize(access_token, secret, options)
        @access_token = access_token
        @secret = secret
        @options = options
      end

      def provider
        'facebook'
      end

      def uid
        raw_info['id']
      end

      def skip_info?
        false
      end

      def image_url(uid, options)
        uri_class = options[:secure_image_url] ? URI::HTTPS : URI::HTTP
        url = uri_class.build({:host => 'graph.facebook.com', :path => "/#{uid}/picture"})

        query = if options[:image_size].is_a?(String)
                  { :type => options[:image_size] }
                elsif options[:image_size].is_a?(Hash)
                  options[:image_size]
                end
        url.query = Rack::Utils.build_query(query) if query

        url.to_s
      end

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end

      def info
        prune!({
                   'nickname' => raw_info['username'],
                   'email' => raw_info['email'],
                   'name' => raw_info['name'],
                   'first_name' => raw_info['first_name'],
                   'last_name' => raw_info['last_name'],
                   'image' => image_url(uid, @options),
                   'description' => raw_info['bio'],
                   'urls' => {
                       'Facebook' => raw_info['link'],
                       'Website' => raw_info['website']
                   },
                   'location' => (raw_info['location'] || {})['name'],
                   'verified' => raw_info['verified']
               })
      end

      def extra
        hash = {}
        hash['raw_info'] = raw_info unless skip_info?
        prune! hash
      end

      def raw_info
        # TODO: Figure out what this does
        #@raw_info ||= @access_token.get('/me', info_options).parsed || {}
        @raw_info ||= @access_token.get('/me', {access_token: @access_token.token}) || {}
      end

      def info_options
        params = {:appsecret_proof => appsecret_proof}
        params.merge!({:fields => @options[:info_fields]}) if @options[:info_fields]
        params.merge!({:locale => @options[:locale]}) if @options[:locale]

        { :params => params }
      end

      def appsecret_proof
        @appsecret_proof ||= OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, @secret, @access_token.token)
      end

      def credentials
        hash = {'token' => @access_token.token}
        hash.merge!('refresh_token' => @access_token.refresh_token) if @access_token.expires? && @access_token.refresh_token
        hash.merge!('expires_at' => @access_token.expires_at) if @access_token.expires?
        hash.merge!('expires' => @access_token.expires?)
        hash
      end
    end
end

# TODO: Put in access_token.rb
module Oauthio
  class AccessToken
    attr_reader :client, :token, :expires_in, :expires_at, :params
    attr_accessor :options, :refresh_token

    class << self
      # Initializes an AccessToken from a Hash
      #
      # @param [Client] the OAuth2::Client instance
      # @param [Hash] a hash of AccessToken property values
      # @return [AccessToken] the initalized AccessToken
      def from_hash(client, hash)
        new(client, hash.delete('access_token') || hash.delete(:access_token), hash)
      end

      # Initializes an AccessToken from a key/value application/x-www-form-urlencoded string
      #
      # @param [Client] client the OAuth2::Client instance
      # @param [String] kvform the application/x-www-form-urlencoded string
      # @return [AccessToken] the initalized AccessToken
      def from_kvform(client, kvform)
        from_hash(client, Rack::Utils.parse_query(kvform))
      end
    end

    # Initalize an AccessToken
    #
    # @param [Client] client the OAuth2::Client instance
    # @param [String] token the Access Token value
    # @param [Hash] opts the options to create the Access Token with
    # @option opts [String] :refresh_token (nil) the refresh_token value
    # @option opts [FixNum, String] :expires_in (nil) the number of seconds in which the AccessToken will expire
    # @option opts [FixNum, String] :expires_at (nil) the epoch time in seconds in which AccessToken will expire
    # @option opts [Symbol] :mode (:header) the transmission mode of the Access Token parameter value
    #    one of :header, :body or :query
    # @option opts [String] :header_format ('Bearer %s') the string format to use for the Authorization header
    # @option opts [String] :param_name ('access_token') the parameter name to use for transmission of the
    #    Access Token value in :body or :query transmission mode
    def initialize(client, token, opts = {})
      @client = client
      @token = token.to_s
      [:refresh_token, :expires_in, :expires_at].each do |arg|
        instance_variable_set("@#{arg}", opts.delete(arg) || opts.delete(arg.to_s))
      end
      @expires_in ||= opts.delete('expires')
      @expires_in &&= @expires_in.to_i
      @expires_at &&= @expires_at.to_i
      @expires_at ||= Time.now.to_i + @expires_in if @expires_in
      @options = {:mode          => opts.delete(:mode) || :header,
                  :header_format => opts.delete(:header_format) || 'Bearer %s',
                  :param_name    => opts.delete(:param_name) || 'access_token'}
      @params = opts
    end

    # Indexer to additional params present in token response
    #
    # @param [String] key entry key to Hash
    def [](key)
      @params[key]
    end

    # Whether or not the token expires
    #
    # @return [Boolean]
    def expires?
      !!@expires_at
    end

    # Whether or not the token is expired
    #
    # @return [Boolean]
    def expired?
      expires? && (expires_at < Time.now.to_i)
    end

    # Refreshes the current Access Token
    #
    # @return [AccessToken] a new AccessToken
    # @note options should be carried over to the new AccessToken
    def refresh!(params = {})
      fail('A refresh_token is not available') unless refresh_token
      params.merge!(:client_id      => @client.id,
                    :client_secret  => @client.secret,
                    :grant_type     => 'refresh_token',
                    :refresh_token  => refresh_token)
      new_token = @client.get_token(params)
      new_token.options = options
      new_token.refresh_token = refresh_token unless new_token.refresh_token
      new_token
    end

    # Convert AccessToken to a hash which can be used to rebuild itself with AccessToken.from_hash
    #
    # @return [Hash] a hash of AccessToken property values
    def to_hash
      params.merge(:access_token => token, :refresh_token => refresh_token, :expires_at => expires_at)
    end

    # Make a request with the Access Token
    #
    # @param [Symbol] verb the HTTP request method
    # @param [String] path the HTTP URL path of the request
    # @param [Hash] opts the options to make the request with
    # @see Client#request
    def request(verb, path, opts = {}, &block)
      self.token = opts
      @client.request(verb, path, opts, &block)
    end

    # Make a GET request with the Access Token
    #
    # @see AccessToken#request
    def get(path, opts = {}, &block)
      request(:get, path, opts, &block)
    end

    # Make a POST request with the Access Token
    #
    # @see AccessToken#request
    def post(path, opts = {}, &block)
      request(:post, path, opts, &block)
    end

    # Make a PUT request with the Access Token
    #
    # @see AccessToken#request
    def put(path, opts = {}, &block)
      request(:put, path, opts, &block)
    end

    # Make a PATCH request with the Access Token
    #
    # @see AccessToken#request
    def patch(path, opts = {}, &block)
      request(:patch, path, opts, &block)
    end

    # Make a DELETE request with the Access Token
    #
    # @see AccessToken#request
    def delete(path, opts = {}, &block)
      request(:delete, path, opts, &block)
    end

    # Get the headers hash (includes Authorization token)
    def headers
      {'Authorization' => options[:header_format] % token}
    end

    private

    def token=(opts) # rubocop:disable MethodLength
      case options[:mode]
        when :header
          opts[:headers] ||= {}
          opts[:headers].merge!(headers)
        when :query
          opts[:params] ||= {}
          opts[:params][options[:param_name]] = token
        when :body
          opts[:body] ||= {}
          if opts[:body].is_a?(Hash)
            opts[:body][options[:param_name]] = token
          else
            opts[:body] << "&#{options[:param_name]}=#{token}"
          end
        # @todo support for multi-part (file uploads)
        else
          fail("invalid :mode option of #{options[:mode]}")
      end
    end
  end
end


module Oauthio
  module Strategy
    class AuthCode < OAuth2::Strategy::AuthCode
      def initialize(client)
        @client = client
      end

      # The required query parameters for the authorize URL
      #
      # @param [Hash] params additional query parameters
      def authorize_params(params={})
        params.merge('k' => @client.id)
      end

      #TODO: Put this in base.rb
      # The OAuth client_id and client_secret
      #
      # @return [Hash]
      def client_params
        {'key' => @client.id, 'secret' => @client.secret}
      end

      # Retrieve an access token given the specified validation code.
      #
      # @param [String] code The Authorization Code value
      # @param [Hash] params additional params
      # @param [Hash] opts options
      # @note that you must also provide a :redirect_uri with most OAuth 2.0 providers
      def get_token(code, params = {}, opts = {})
        params = {'code' => code}.merge(client_params).merge(params)
        @client.get_token(params, opts)
      end
    end
  end
end

# TODO: MOVE THIS TO client.rb
module Oauthio
  class Client < ::OAuth2::Client
    attr_reader :id, :secret, :site
    attr_accessor :options
    attr_writer :connection

    # Instantiate a new OAuth 2.0 client using the
    # Client ID and Client Secret registered to your
    # application.
    #
    # @param [String] client_id the client_id value
    # @param [String] client_secret the client_secret value
    # @param [Hash] opts the options to create the client with
    # @option opts [String] :site the OAuth2 provider site host
    # @option opts [String] :authorize_url ('/oauth/authorize') absolute or relative URL path to the Authorization endpoint
    # @option opts [String] :token_url ('/oauth/token') absolute or relative URL path to the Token endpoint
    # @option opts [Symbol] :token_method (:post) HTTP method to use to request token (:get or :post)
    # @option opts [Hash] :connection_opts ({}) Hash of connection options to pass to initialize Faraday with
    # @option opts [FixNum] :max_redirects (5) maximum number of redirects to follow
    # @option opts [Boolean] :raise_errors (true) whether or not to raise an OAuth2::Error
    #  on responses with 400+ status codes
    # @yield [builder] The Faraday connection builder
    def initialize(client_id, client_secret, opts = {}, &block)
      _opts = opts.dup
      @id = client_id
      @secret = client_secret
      @site = _opts.delete(:site)
      ssl = _opts.delete(:ssl)
      @options = {:authorize_url    => '/auth',
                  :token_url        => '/auth/access_token',
                  :token_method     => :post,
                  :connection_opts  => {},
                  :connection_build => block,
                  :max_redirects    => 5,
                  :raise_errors     => true}.merge(_opts)
      @options[:connection_opts][:ssl] = ssl if ssl
    end

    # Set the site host
    #
    # @param [String] the OAuth2 provider site host
    def site=(value)
      @connection = nil
      @site = value
    end

    # The Faraday connection object
    def connection
      @connection ||= begin
        conn = Faraday.new(site, options[:connection_opts])
        conn.build do |b|
          options[:connection_build].call(b)
        end if options[:connection_build]
        conn
      end
    end

    # The authorize endpoint URL of the OAuth2 provider
    #
    # @param [Hash] params additional query parameters
    def authorize_url(params = nil)
      connection.build_url(options[:authorize_url], params).to_s
    end

    # The token endpoint URL of the OAuth2 provider
    #
    # @param [Hash] params additional query parameters
    def token_url(params = nil)
      connection.build_url(options[:token_url], params).to_s
    end

    # Makes a request relative to the specified site root.
    #
    # @param [Symbol] verb one of :get, :post, :put, :delete
    # @param [String] url URL path of request
    # @param [Hash] opts the options to make the request with
    # @option opts [Hash] :params additional query parameters for the URL of the request
    # @option opts [Hash, String] :body the body of the request
    # @option opts [Hash] :headers http request headers
    # @option opts [Boolean] :raise_errors whether or not to raise an OAuth2::Error on 400+ status
    #   code response for this request.  Will default to client option
    # @option opts [Symbol] :parse @see Response::initialize
    # @yield [req] The Faraday request
    def request(verb, url, opts = {}) # rubocop:disable CyclomaticComplexity, MethodLength
      url = connection.build_url(url, opts[:params]).to_s

      response = connection.run_request(verb, url, opts[:body], opts[:headers]) do |req|
        yield(req) if block_given?
      end

      # Only really care about the status and the actual return body.
      # Oauth2 strategy wraps the response in a Response object that handles parsing and whatnot. That is great when
      # support for multiple options is needed, however we only have to conform to a single interface. We will take
      # the easy route of always expecting a json response.
      status = response.status
      headers = response.headers
      response = JSON.parse(response.body)
      response['status'] = status
      response['headers'] = headers
      response = Hashie::Mash.new response

      case response.status
        when 301, 302, 303, 307
          opts[:redirect_count] ||= 0
          opts[:redirect_count] += 1
          return response if opts[:redirect_count] > options[:max_redirects]
          if response.status == 303
            verb = :get
            opts.delete(:body)
          end
          request(verb, response.headers['location'], opts)
        when 200..299, 300..399
          # on non-redirecting 3xx statuses, just return the response
          response
        when 400..599
          error = Error.new(response)
          fail(error) if opts.fetch(:raise_errors, options[:raise_errors])
          response.error = error
          response
        else
          error = Error.new(response)
          fail(error, "Unhandled status code value of #{response.status}")
      end
    end

    # Initializes an AccessToken by making a request to the token endpoint
    #
    # @param [Hash] params a Hash of params for the token endpoint
    # @param [Hash] access token options, to pass to the AccessToken object
    # @param [Class] class of access token for easier subclassing OAuth2::AccessToken
    # @return [AccessToken] the initalized AccessToken
    def get_token(params, access_token_opts = {}, access_token_class = AccessToken)
      opts = {:raise_errors => options[:raise_errors], :parse => params.delete(:parse)}
      if options[:token_method] == :post
        headers = params.delete(:headers)
        opts[:body] = params
        opts[:headers] =  {'Content-Type' => 'application/x-www-form-urlencoded'}
        opts[:headers].merge!(headers) if headers
      else
        opts[:params] = params
      end
      response = request(options[:token_method], token_url, opts)

      #error = Error.new(response)
      #fail(error) if options[:raise_errors] && !(response.parsed.is_a?(Hash) && response.parsed['access_token'])

      #access_token_class.from_hash(providerClient, response.merge(access_token_opts))

      provider_client = ::Oauthio::Client.new(@id, @secret, { :site => response.request.url })
      access_token_class.from_hash(provider_client, response.merge(access_token_opts))
    end

    # The Authorization Code strategy
    #
    # @see http://tools.ietf.org/html/draft-ietf-oauth-v2-15#section-4.1
    def auth_code
      @auth_code ||= Oauthio::Strategy::AuthCode.new(self)
    end

    # The Implicit strategy
    #
    # @see http://tools.ietf.org/html/draft-ietf-oauth-v2-26#section-4.2
    def implicit
      @implicit ||= OAuth2::Strategy::Implicit.new(self)
    end

    # The Resource Owner Password Credentials strategy
    #
    # @see http://tools.ietf.org/html/draft-ietf-oauth-v2-15#section-4.3
    def password
      @password ||= OAuth2::Strategy::Password.new(self)
    end

    # The Client Credentials strategy
    #
    # @see http://tools.ietf.org/html/draft-ietf-oauth-v2-15#section-4.4
    def client_credentials
      @client_credentials ||= OAuth2::Strategy::ClientCredentials.new(self)
    end

    def assertion
      @assertion ||= OAuth2::Strategy::Assertion.new(self)
    end
  end
end

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




