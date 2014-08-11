omniauth-oauthio
=================

OAuth.io Strategy for OmniAuth

# TODO

Please note this strategy is still pretty experimental and is not complete

1. I am using this mainly with a pure javascript/angularjs single page application that connects to a rails api, but
there is no reason why this potentially work with a normal rails application that takes does not require javascript.
I believe there is some missing functionality there and requires further testing.

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
  configure do |config|
    config.path_prefix = '/users/auth'
  end
end
```

The following steps on the front-end need to occur:

1. Initialize the OAuth public key.

2. Perform get request to initiate the request_phase, using the .json option for SPA (This is to get a state string from the server).

3. Use OAuth.io's javascript api to initiate a popup (Passing along the state from step 2).

4. Perform get request to initiate callback_phase (Passing along the state and code received in step 3).

For example:  (NOTE: I need to update this. I am currently using dart in my test app)

```coffeescript
OAuth.initialize('YOUR_PUBLIC_KEY')

$.get "http://localhost:3000/users/auth/oauthio.json", (data) ->
    @options = data

OAuth.popup provider, @options, (err, res) ->
    if (err)
      console.log err
    else
      $.get "http://localhost:3000/users/auth/oauthio/twitter/callback.json?state=@options.state&code=@options.code", (data) ->
        console.log(data)
        # Perform additional login steps
```

## Configuring

### OAuth.io

Be sure to enable the Server-side (code) option on any providers you want to use with this strategy.

### Custom Callback URL/Path

You can set a custom `callback_url` or `callback_path` option to override the default value. See [OmniAuth::Strategy#callback_url](https://github.com/intridea/omniauth/blob/master/lib/omniauth/strategy.rb#L411) for more details on the default.

### Devise
To use with devise, in `config/initializers/devise.rb`

```ruby
config.omniauth :oauthio, ENV['OAUTHIO_PUBLIC_KEY'], ENV['OAUTHIO_SECRET_KEY']
```

Add your devise routes in `config/routes.rb`

```ruby
devise_for :users, :skip => [:omniauth_callbacks]
devise_scope :user do
  match "/users/auth/:provider(/:sub_provider)",
        constraints: { provider: /oauthio/ },
        to: "users/omniauth_callbacks#passthru",
        as: :omniauth_authorize,
        via: [:get, :post]

  match "/users/auth/:action(/:sub_provider)/callback",
        constraints: { action: /oauthio/, sub_provider: /twitter|google/ },
        to: "users/omniauth_callbacks",
        as: :omniauth_callback,
        via: [:get, :post]
end
```

### Omniauth

Add an oauthio callback in `app/controllers/users/omniauth_callbacks_controller.rb`

```ruby

class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  def oauthio

    # TODO: Do your login logic here! ie. look up the user by the uid or create one if it does not already exist!

    respond_to do |format|
      format.json  { render json: auth_hash}
    end
  end

  def auth_hash
    request.env['omniauth.auth']
  end

end
```

Create the method used in your callback in your `user.rb`

# Understanding server side flow

oauth.io describes how everything works in their [security](https://oauth.io/docs/security) section.

![alt text](https://oauth.io/img/server-side-flow.png "Server side flow")


## Credit

https://oauth.io/

https://github.com/mkdynamic/omniauth-facebook
