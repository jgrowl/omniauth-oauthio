require 'bundler/setup'
require 'omniauth-oauthio'
require 'sinatra'
require_relative 'app.rb'

use Rack::Session::Cookie, :secret => 'abc123'

use OmniAuth::Builder do
  provider :oauthio, ENV['OAUTHIO_PUBLIC_KEY'], ENV['OAUTHIO_PRIVATE_KEY']
end

run Sinatra::Application
