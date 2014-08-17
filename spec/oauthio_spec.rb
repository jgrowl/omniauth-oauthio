RSpec.describe OmniAuth::Strategies::Oauthio do
  let(:provider) { 'facebook' }
  let(:env) {
    OmniAuth::AuthHash.new({
      'omniauth.auth' => {
        'provider' => provider,
        'uid' => '1234',
        'credentials' => {'token' => 'abcdefg'},
        'extra' => {
          'raw_info' => {
            'id' => '1234567',
            'email' => 'j.doe@example.com',
            'name' => 'Jane Doe',
            'gender' => 'female'
          }
        }
      }
    })
  }
  let(:request) {
    mock = double('Request', :params => {}, :cookies => {}, :env => env)
    allow(mock).to receive(:path).and_return("/auth/oauthio/#{provider}")
    mock
  }
  let(:app) { ->(env) { [200, {}, ['Hello.']] } }
  let(:client_id) { '123' }
  let(:client_secret) { '53cr37' }
  let(:options) { {:callback_path => '/auth/oauthio/done'} }
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
end
