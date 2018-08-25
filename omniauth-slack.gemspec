# coding: utf-8
require File.expand_path('../lib/omniauth-slack/version', __FILE__)

Gem::Specification.new do |spec|
  spec.name          = 'omniauth-slack'
  spec.version       = Omniauth::Slack::VERSION
  spec.authors       = ['kimura', 'ginjo']
  spec.email         = ['kimura@enigmo.co.jp', 'wbr@mac.com']
  spec.description   = %q{OmniAuth strategy for Slack}
  spec.summary       = %q{OmniAuth strategy for Slack, based on the oauth2 and omniauth-oauth2 gems}
  spec.homepage      = 'https://github.com/kmrshntr/omniauth-slack.git'
  spec.license       = 'MIT'

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'omniauth-oauth2', '~> 1.4'

  if RUBY_PLATFORM =~ /java/
    spec.add_development_dependency 'bundler', '>= 1.11.2'
  else
    spec.add_development_dependency 'bundler', '>= 1.11.2'
  end
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'minitest'
  spec.add_development_dependency 'mocha'
end
