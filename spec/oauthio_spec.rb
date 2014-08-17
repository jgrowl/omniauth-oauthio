RSpec.describe OmniAuth::Strategies::Oauthio do
  let(:provider) { 'facebook' }
  let(:scheme) { 'https' }
  let(:path) { "/auth/oauthio/#{provider}" }
  let(:url) { "#{scheme}://example.com#{path}" }
  let(:client_id) { '123' }
  let(:client_secret) { '53cr37' }
  let(:options) { {} }
  let(:raw_info) {
    {'id' => '1234567', 'email' => 'j.doe@example.com', 'name' => 'Jane Doe',
     'gender' => 'female'}
  }
  let(:env) {
    OmniAuth::AuthHash.new({
      'omniauth.auth' => {
        'provider' => provider,
        'uid' => '1234',
        'credentials' => {'token' => 'abcdefg'},
        'extra' => {'raw_info' => raw_info}
      },
      'REQUEST_METHOD' => 'GET',
      'PATH_INFO' => path,
      'rack.session' => {},
      'rack.input' => StringIO.new('test=true')
    })
  }
  let(:request) {
    mock = double('Request', :params => {}, :cookies => {}, :env => env)
    allow(mock).to receive(:path).and_return(path)
    allow(mock).to receive(:path_info).and_return(path)
    allow(mock).to receive(:scheme).and_return(scheme)
    allow(mock).to receive(:url).and_return(url)
    mock
  }
  let(:app) { ->(env) { [200, {}, ['Hello.']] } }
  subject {
    args = [app, client_id, client_secret, options]
    OmniAuth::Strategies::Oauthio.new(*args).tap do |strategy|
      allow(strategy).to receive(:request) { request }
    end
  }

  before { OmniAuth.config.test_mode = true }
  after { OmniAuth.config.test_mode = false }

  describe 'sub_provider' do
    it 'extracts the OAuth provider from the request path' do
      expect(subject.sub_provider).to eq(provider)
    end
  end

  describe 'request_path' do
    context 'without request_path option' do
      it 'returns path for provider' do
        expect(subject.request_path).to eq("/auth/oauthio/#{provider}")
      end
    end

    context 'with request_path option' do
      let(:options) { {:request_path => '/authentication/oauthio'} }

      it 'returns specified request_path' do
        expect(subject.request_path).to eq(options[:request_path])
      end
    end
  end

  describe 'callback_path' do
    context 'without callback_path or request_path options' do
      it 'returns a callback URL for the provider' do
        expect(subject.callback_path).
            to eq("/auth/oauthio/#{provider}/callback")
      end
    end

    context 'with string request_path option' do
      let(:options) { {:request_path => '/some/neat/url'} }

      it 'returns specified request_path' do
        expect(subject.callback_path).to eq(options[:request_path])
      end
    end

    context 'with lambda request_path option' do
      let(:options) { {:request_path => ->(env) { '/really/cool' }} }

      it 'returns result of specified request_path function' do
        expect(subject.callback_path).to eq('/really/cool')
      end
    end

    context 'with lambda callback_path option' do
      let(:options) { {:callback_path => ->(env) { 'something truthy' }} }

      it 'returns current path' do
        expect(subject.callback_path).to eq(path)
      end
    end

    context 'with string callback_path option' do
      let(:options) { {:callback_path => "/users/auth/#{provider}/callback"} }

      it 'returns specified callback_path' do
        expect(subject.callback_path).to eq(options[:callback_path])
      end
    end
  end

  describe 'callback_url_with_state' do
    let(:state) { 'cool' }
    before { subject.call!(env) }

    it 'returns full URL with specified state' do
      expect(subject.callback_url_with_state(state)).
          to eq("#{url}/callback?state=#{state}")
    end
  end

  describe 'auth_hash' do
    let(:client) { Oauthio::Client.new(client_id, client_secret, {}) }
    let(:access_token) {
      token = Oauthio::AccessToken.from_hash(client, {:provider => provider})
      allow(token).to receive(:request).and_return({'data' => raw_info})
      token
    }
    before do
      subject.call!(env)
      allow(subject).to receive(:access_token).and_return(access_token)
    end

    it 'returns a hash' do
      expect(subject.auth_hash).to be_an_instance_of(OmniAuth::AuthHash)
    end

    it 'includes specified provider' do
      expect(subject.auth_hash['provider']).to eq(provider)
    end

    it 'has user info from provider' do
      expect(subject.auth_hash.info).to eq(raw_info)
    end
  end
end
