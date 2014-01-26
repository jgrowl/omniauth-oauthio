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
  provider :oauthio, ENV['OAUTHIO_PUBLIC_KEY'], ENV['OAUTHIO_SECRET_KEY']
end
```

Use OAuth javascript API, adding a post request to the success callback:

```coffeescript
OAuth.initialize('YOUR_PUBLIC_KEY')
OAuth.popup provider, {state: A_RANDOM_STATE_ID}, (err, res) ->
    if (err)
      console.log err
    else
        $http.post('http://example.com/users/auth/oauthio/callback', JSON.stringify(res)).success((response) ->
            console.log 'successfully logged user in!'
            # Perform additional login steps
          ).error((response) ->
            console.log 'error making post to callback'
          )
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

## Credit

https://oauth.io/
https://github.com/mkdynamic/omniauth-facebook
