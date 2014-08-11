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
        prune!({
                   'name' => _raw_info['name'],
                   'alias' => _raw_info['alias'],
                   'bio' => _raw_info['bio'],
                   'avatar' => _raw_info['avatar'],
                   'firstname' => _raw_info['firstname'],
                   'lastname' => _raw_info['lastname'],
                   'gender' => _raw_info['gender'],
                   'location' => _raw_info['location'],
                   'local' => _raw_info['local'],
                   'company' => _raw_info['company'],
                   'occupation' => _raw_info['occupation'],
                   'language' => _raw_info['language'],
                   'birthdate' => _raw_info['birthdate'],
               })
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
        @raw_info ||= _raw_info['raw']  || {}
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
        hash.merge!('token' => @access_token.token) if !@access_token.token.empty?
        hash.merge!('oauth_token' => @access_token.oauth_token,
                    'oauth_token_secret' => @access_token.oauth_token_secret) if !@access_token.oauth_token.empty? && !@access_token.oauth_token_secret.empty?
        hash.merge!('refresh_token' => @access_token.refresh_token) if @access_token.expires? && @access_token.refresh_token
        hash.merge!('expires_at' => @access_token.expires_at) if @access_token.expires?
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
