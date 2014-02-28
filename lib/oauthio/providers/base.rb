module Oauthio
  module Base
    def prune!(hash)
      hash.delete_if do |_, v|
        prune!(v) if v.is_a?(Hash)
        v.nil? || (v.respond_to?(:empty?) && v.empty?)
      end
    end
  end
end
