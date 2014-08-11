module Oauthio
  class AccessToken < OAuth2::AccessToken
    attr_reader :provider, :oauth_token, :oauth_token_secret

    class << self
      # Initializes an AccessToken from a Hash
      #
      # @param [Client] the OAuth2::Client instance
      # @param [Hash] a hash of AccessToken property values
      # @return [AccessToken] the initalized AccessToken
      def from_hash(client, hash)
        new(client,
            hash.delete('provider') || hash.delete(:provider),
            hash.delete('access_token') || hash.delete(:access_token),
            hash.delete('oauth_token') || hash.delete(:oauth_token),
            hash.delete('oauth_token_secret') || hash.delete(:oauth_token_secret),
            hash)
      end
    end

    def initialize(client, provider, token, oauth_token, oauth_token_secret, opts = {})
      super client, token, opts
      @provider = provider
      @oauth_token = oauth_token.to_s
      @oauth_token_secret = oauth_token_secret.to_s
    end

    def me()
      k = @client.id
      # oauthv = 1  # TODO: Update this

      if !@token.empty?
        # oauthv=#{oauthv}
        oauthio_header = "k=#{k}&access_token=#{@token}"
      elsif !@oauth_token.empty? && !@oauth_token_secret.empty?
        # oauthv=#{oauthv}
        oauthio_header = "k=#{k}&oauth_token=#{@oauth_token}&oauth_token_secret=#{@oauth_token_secret}"
      else
        # TODO: Throw error if no tokens found
      end
      opts = {headers: {oauthio: oauthio_header}}
      me_url = client.me_url(provider)
      request(:get, me_url, opts)
    end
  end
end