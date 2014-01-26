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