require 'sinatra'
require 'sinatra/reloader'
require 'yaml'

# configure sinatra
set :run, false
set :raise_errors, true

# setup logging to file
log = File.new('app.log', 'a+')
$stdout.reopen(log)
$stderr.reopen(log)
$stderr.sync = true
$stdout.sync = true

# server-side flow
get '/server-side/:provider' do
  # NOTE: You would just hit this endpoint directly from the browser in a real
  # app. The redirect is just here to explicitly declare this server-side flow.
  redirect "/auth/oauthio/#{params[:provider]}"
end

# client-side flow
get '/client-side' do
  content_type 'text/html'
  <<-END.gsub(/^\s{4}/, '')
    <html>
    <head>
      <title>Client-side Flow Example</title>
      <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.7.0/jquery.min.js" type="text/javascript"></script>
      <script src="https://rawgit.com/oauth-io/oauth-js/master/dist/oauth.min.js" type="text/javascript"></script>
    </head>
    <body>
      <div id="oauthio-root"></div>

      <script type="text/javascript">
        var qs = (function(a) {
            if (a == "") return {};
            var b = {};
            for (var i = 0; i < a.length; ++i)
            {
                var p=a[i].split('=');
                if (p.length != 2) continue;
                b[p[0]] = decodeURIComponent(p[1].replace(/\\+/g, " "));
            }
            return b;
        })(window.location.search.substr(1).split('&'));

        OAuth.initialize('#{ENV['OAUTHIO_PUBLIC_KEY']}');

        window.onload = function(){
          if (qs['provider'] != undefined) {
            var promise = OAuth.callback(qs['provider']);

            promise.done(function (result) {
              result.me().done(function(me){
                  $('#me').html(JSON.stringify(me));
                  $.post("/auth/oauthio/" + qs['provider'] + "/callback.json", {'state': qs['state'], 'code': result.code})
                    .done(function(r){
                      $('#results').html(JSON.stringify(r));
                    });
              });
            });

            promise.fail(function (error) {
                // handle errors
              console.log(error);
            });
          }
        }

        $(function() {
          $('p#connect a').click(function(e) {
            e.preventDefault();
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
            });
          });

          $('p#no-sdk-connect a').click(function(e) {
            e.preventDefault();
            var selectedProvider = $('#provider').val();
            document.location = document.location.origin + "/auth/oauthio/" + selectedProvider
          });

        });
      </script>

      <select id="provider">
        <option value="facebook">Facebook</option>
        <option value="twitter" selected>Twitter</option>
        <option value="google">Google</option>
      </select>

      <select id="type">
        <option value="popup" selected>Popup</option>
        <option value="redirect">Redirect</option>
      </select>

      <p id="connect">
        <a href="#">Connect!</a>
      </p>

      <p id="no-sdk-connect">
        <a href="/auth/oauthio/twitter">Redirect w/o JS SDK!</a>
      </p>

      <p id="me" />
      <p id="results" />
    </body>
    </html>
  END
end

def self.get_or_post(url, &block)
  get(url,&block)
  post(url,&block)
end

get_or_post '/auth/:provider/:sub_provider/callback.?:format?' do
  content_type 'application/json'
  MultiJson.encode(request.env)
end

get '/auth/failure' do
  content_type 'application/json'
  MultiJson.encode(request.env)
end
