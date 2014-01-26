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