# -*- encoding: utf-8 -*-
$:.push File.expand_path('../lib', __FILE__)
require 'omniauth/oauth-io/version'

Gem::Specification.new do |s|
  s.name     = 'omniauth-oauth-io'
  s.version  = OmniAuth::OauthIo::VERSION
  s.authors  = ['Jonathan Rowlands']
  s.email    = ['jonrowlands83@gmail.com']
  s.summary  = 'OAuth.io Strategy for OmniAuth'
  s.homepage = 'https://github.com/jgrowl/omniauth-oauth-io'
  s.license  = 'MIT'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  s.require_paths = ['lib']

  s.add_runtime_dependency 'omniauth-oauth2', '~> 1.1'

  s.add_development_dependency 'minitest'
  s.add_development_dependency 'mocha'
  s.add_development_dependency 'rake'
end
