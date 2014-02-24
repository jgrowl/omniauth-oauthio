omniauth-oauthio
=================

OAuth.io Strategy for OmniAuth

# TODO

Please note this strategy is still pretty experimental and is not complete

1. I am using this mainly with a pure javascript/angularjs single page application that connects to a rails api, but
there is no reason why this potentially work with a normal rails application that takes does not require javascript.
I believe there is some missing functionality there and requires further testing.

2. Currently, only facebook is supported. The main goal is that this could use every provider that oauth-io supports.
There will have to be some work for that to happen though. A large part of every omniauth strategy is the marshalling
of provider specific user information into a hash (credentials, info, and extra). There are two options I see: create
a methods to perform this marshalling in omniauth-oauthio for each provider. This is what I am currently doing but it
is less than ideal. The other option is modify oauthd to provide a standardized way of gathering this info. That is
the clean way of doing it but would require work and acceptance by the oauthio guys.

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
  provider :oauthio, ENV['OAUTHIO_PUBLIC_KEY'], ENV['OAUTHIO_SECRET_KEY']
end
```

The following steps on the front-end need to occur:

1. Initialize the OAuth public key.

2. Perform get request to initiate the request_phase, using the json=true option for SPA.

3. Perform get request to initiate callback_phase.

For example:

```coffeescript
OAuth.initialize('YOUR_PUBLIC_KEY')

$.get "http://localhost:3000/users/auth/oauthio?json=true", (data) ->
    @options = data

# Create a function that takes a provider as an argument to support multiple providers
provider = 'facebook'

OAuth.popup provider, @options, (err, res) ->
    if (err)
      console.log err
    else
      $.get "http://localhost:3000/users/auth/oauthio/callback?state=@options.state", (data) ->
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
require 'omniauth-oauthio'
config.omniauth :oauthio, ENV['OAUTHIO_PUBLIC_KEY'], ENV['OAUTHIO_SECRET_KEY']
```

### Omniauth

Add an oauthio callback in `app/controllers/users/omniauth_callbacks_controller.rb`

```ruby
def oauthio
    # You need to implement the method below in your model (e.g. app/models/user.rb)
    @user = User.find_for_oauthio_oauth(auth_hash, current_user)
    provider = auth_hash.provider

    if @user.persisted?
      sign_in @user
      render json: {success: true}
    else
      session["devise.#{provider}_data"] = auth_hash
      render json: {success: false, message: 'There was a problem adding user!'}
    end
end

def auth_hash
    request.env['omniauth.auth']
end
```

Create the method used in your callback in your `user.rb`

```ruby
def self.find_for_oauthio_oauth(auth, signed_in_resource=nil)
    oauth_token = auth.credentials.token
    user = User.where(:provider => auth.provider, :uid => auth.uid).first

    if user
      user.oauth_token = oauth_token
      user.save
    else
      user = User.create(
                          #name: auth.extra.raw_info.name,
                         provider: auth.provider,
                         uid: auth.uid,
                         email: auth.info.email,
                         password: Devise.friendly_token[0, 20],
                         oauth_token: oauth_token
      )
    end
    user
end
```

# Understanding server side flow

oauth.io describes how everything works in their [security](https://oauth.io/docs/security) section.

![alt text](https://oauth.io/img/server-side-flow.png "Server side flow")


## Credit

https://oauth.io/

https://github.com/mkdynamic/omniauth-facebook
