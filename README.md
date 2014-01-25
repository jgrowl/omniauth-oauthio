omniauth-oauthio
=================

OAuth.io Strategy for OmniAuth

## Installing

Add to your `Gemfile`:

```ruby
gem 'omniauth-oauthio', path: 'https://github.com/jgrowl/omniauth-oauthio.git'
```

Then `bundle install`.

## Usage

`OmniAuth::Strategies::Oauthio` is simply a Rack middleware. Read the OmniAuth docs for detailed instructions: https://github.com/intridea/omniauth.

Here's a quick example, adding the middleware to a Rails app in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :facebook, ENV['FACEBOOK_KEY'], ENV['FACEBOOK_SECRET']
end
```

## Configuring

### Custom Callback URL/Path

You can set a custom `callback_url` or `callback_path` option to override the default value. See [OmniAuth::Strategy#callback_url](https://github.com/intridea/omniauth/blob/master/lib/omniauth/strategy.rb#L411) for more details on the default.

### Devise
To use with devise, in `config/initializers/devise.rb`

```ruby
require 'omniauth-oauthio'
config.omniauth :oauthio, ENV['OAUTHIO_PUBLIC_KEY'], ENV['OAUTHIO_SECRET_KEY']
```

