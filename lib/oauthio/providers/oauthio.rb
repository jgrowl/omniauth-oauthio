module Oauthio
  module Providers
    class Oauthio
      def initialize(access_token, secret, options)
        @access_token = access_token
        @secret = secret
        @options = options
      end

      def uid
        # This might not be uniform across all providers. Need to talk to oauthd guys to see if we can get the id
        # in the list of things parsed out of the raw data.
        raw_info['id']
      end

      def skip_info?
        false
      end

      def info
        prune!(_raw_info)
      end

      def extra
        hash = {}
        hash['raw_info'] = raw_info unless skip_info?
        prune! hash
      end

      def _raw_info
        @_raw_info ||= @access_token.me()['data'] || {}
        @_raw_info
      end

      def raw_info
        @raw_info ||= _raw_info['raw'] || {}
      end

      def info_options
        # params = {:appsecret_proof => appsecret_proof}
        # params.merge!({:fields => @options[:info_fields]}) if @options[:info_fields]
        # params.merge!({:locale => @options[:locale]}) if @options[:locale]
        #
        # {:params => params}
      end

      def appsecret_proof
        # @appsecret_proof ||= OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, @secret, @access_token.token)
      end

      def credentials
        hash = {}
        unless @access_token.token.empty?
          hash.merge!('token' => @access_token.token)
        end
        has_oauth_token = !@access_token.oauth_token.empty?
        has_oauth_token_secret = !@access_token.oauth_token_secret.empty?
        if has_oauth_token && has_oauth_token_secret
          hash.merge!('oauth_token' => @access_token.oauth_token,
                      'oauth_token_secret' => @access_token.oauth_token_secret)
        end
        if @access_token.expires? && @access_token.refresh_token
          hash.merge!('refresh_token' => @access_token.refresh_token)
        end
        if @access_token.expires?
          hash.merge!('expires_at' => @access_token.expires_at)
        end
        hash.merge!('expires' => @access_token.expires?)
        hash
      end

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end
    end
  end
end
