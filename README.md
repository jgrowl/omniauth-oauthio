omniauth-oauthio
=================

OAuth.io Strategy for OmniAuth

## Installing

Add to your `Gemfile`:

```ruby
gem 'omniauth-oauthio', '~> 0.2.0'
```

Then `bundle install`.

## Usage

The following steps on the front-end need to occur:

1. Initialize the OAuth public key.

2. Perform a request to initiate the request_phase (/auth/oauthio/:provider), using the .json option for SPA (This is to get a state string from the server).

3. Optionally, use OAuth.io's javascript api to initiate a popup or a redirect (Passing along the state from step 2).

4. Perform a request to initiate callback_phase (/auth/oauthio/:provider/callback) (Passing along the state and code received in step 3).

For example:

```javascript
OAuth.initialize('YOUR_PUBLIC_KEY');
        
var selectedProvider = $('#provider').val();
var type = $('#type').val();

$.get("/auth/oauthio/" + selectedProvider + ".json").done(function(data){
  var state = data.state
  if (type == 'popup') {
    OAuth.popup(selectedProvider, {'state': state})
        .done(function(result) {
          //use result.access_token in your API request
          //or use result.get|post|put|del|patch|me methods (see below)
          result.me().done(function(me){
            $('#me').html(JSON.stringify(me));
            $.post("/auth/oauthio/" + selectedProvider + "/callback.json", {'state': state, 'code': result.code})
              .done(function(r){
                $('#results').html(JSON.stringify(r));
              });
          });
        })
        .fail(function (err) {
          //handle error with err
          console.log(err);
          $('#results').html(err.message)
        });
  } else if (type == 'redirect') {
    OAuth.redirect(selectedProvider, {'state': state}, '/client-side?provider=' + selectedProvider + '&state=' + state);
  }
```

## Configuring

### Rails

Set the path_prefix. In `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  configure do |config|
    config.path_prefix = '/users/auth'
  end
end
```

#### Devise

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

### OAuth.io

Be sure to enable the Server-side (code) option on any providers you want to use with this strategy.

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
