# -*- encoding: utf-8 -*-
$:.push File.expand_path('../lib', __FILE__)
require 'omniauth/oauthio/version'

Gem::Specification.new do |s|
  s.name     = 'omniauth-oauthio'
  s.version  = OmniAuth::Oauthio::VERSION
  s.authors  = ['Jonathan Rowlands']
  s.email    = ['jonrowlands83@gmail.com']
  s.summary  = 'OAuth.io Strategy for OmniAuth'
  s.homepage = 'https://github.com/jgrowl/omniauth-oauthio'
  s.license  = 'MIT'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.require_paths = ['lib']

  s.add_runtime_dependency 'omniauth-oauth2', '~> 1.2'
  s.add_runtime_dependency 'jwt'

  s.add_development_dependency 'mocha'
  s.add_development_dependency 'rake'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'simplecov'
end
