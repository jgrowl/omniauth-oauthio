omniauth-oauthio
=================

[OAuth.io](https://oauth.io/) Strategy for OmniAuth

[![Gem Version](https://badge.fury.io/rb/omniauth-oauthio.svg)](http://badge.fury.io/rb/omniauth-oauthio)

## Installing

Add to your `Gemfile`:

```ruby
gem 'omniauth-oauthio', '~> 0.2.1'
```

Then `bundle install`.

## Usage

The following steps on the front-end need to occur:

1. Initialize the OAuth public key.

2. Perform a request to initiate the request_phase `/auth/oauthio/:provider`, using the .json option for a single-page application (this is to get a state string from the server).

3. Optionally, use OAuth.io's JavaScript API to initiate a popup or a redirect, passing along the state from step 2.

4. Perform a request to initiate callback_phase `/auth/oauthio/:provider/callback`, passing along the state and code received in step 3.

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

Set `path_prefix` in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  configure do |config|
    config.path_prefix = '/users/auth'
  end
end
```

#### Devise

To use with [Devise](https://github.com/plataformatec/devise), in `config/initializers/devise.rb`

```ruby
config.omniauth :oauthio, ENV['OAUTHIO_PUBLIC_KEY'], ENV['OAUTHIO_SECRET_KEY']
```

Add your Devise routes in `config/routes.rb`:

```ruby
devise_for :users, :skip => [:omniauth_callbacks]
devise_scope :user do
  match '/users/auth/:action(/:sub_action)',
        constraints: {:action => /oauthio/},
        to: 'users/omniauth_callbacks#passthru',
        as: :omniauth_authorize, via: [:get, :post]

  match '/users/auth/:action(/:sub_action)/callback',
        constraints: {:action => /oauthio/},
        to: 'users/omniauth_callbacks',
        as: :omniauth_callback, via: [:get, :post]
end
```

`sub_action` options are available if you would like to limit the actual providers allowed on the Rails side:

```ruby
constraints: {:action => /oauthio/, :sub_action => /twitter|google/}
```

### OAuth.io

Be sure to enable the server-side (code) option on any providers you want to use with this strategy.

### Omniauth

Add an `oauthio` callback in `app/controllers/users/omniauth_callbacks_controller.rb`:

```ruby
class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  def oauthio
    # TODO: Do your login logic here!
    # e.g., look up the user by the uid or create one if it does not already
    # exist!

    respond_to do |format|
      format.json  { render json: request.env['omniauth.auth'] }
    end
  end
end
```

## Understanding server-side flow

OAuth.io describes how everything works in [their security section](https://oauth.io/docs/security):

![alt text](https://oauth.io/img/server-side-flow.png "Server side flow")

## Running Sample Application

In `example/` there is a simple Sinatra app that uses this gem. You can test Facebook, Twitter, and Google authentication with it. For these providers to work, you'll have to set them up on the provider website, e.g., [Facebook Developers](https://developers.facebook.com), as well as in OAuth.io.

To start the sample app:

    cd example
    bundle
    OAUTHIO_PUBLIC_KEY=yourkey OAUTHIO_PRIVATE_KEY=yourprivatekey rackup

Then visit [http://localhost:9292](http://localhost:9292) in your browser.

## Credit

- [OAuth.io](https://oauth.io/)
- [omniauth-facebook](https://github.com/mkdynamic/omniauth-facebook)
