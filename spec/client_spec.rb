RSpec.describe Oauthio::Client do
  let(:site) { 'https://oauth.io' }
  let(:client_id) { '123' }
  let(:client_secret) { '53cr37' }
  let(:client) { Oauthio::Client.new(client_id, client_secret, options) }

  describe 'me_url' do
    let(:provider) { 'google' }
    subject { client.me_url(provider, params) }

    context 'when me_url option is not specified' do
      let(:options) { {:site => site} }

      context 'without URL parameters' do
        let(:params) { {} }

        it 'replaces provider in URL' do
          expect(subject).to eq("#{site}/auth/#{provider}/me")
        end
      end

      context 'with URL parameters' do
        let(:params) { {'foo' => 'bar', 'cat' => 'dog'} }

        it 'includes given URL parameters' do
          expect(subject).to eq("#{site}/auth/#{provider}/me?cat=dog&foo=bar")
        end
      end
    end

    context 'when me_url option is specified' do
      let(:options) {
        {:site => site, :me_url => '/big-cats/catch-mice/:provider'}
      }

      context 'without URL parameters' do
        let(:params) { {} }

        it 'replaces provider in URL' do
          expect(subject).to eq("#{site}/big-cats/catch-mice/#{provider}")
        end
      end

      context 'with URL parameters' do
        let(:params) { {'foo' => 'bar', 'cat' => 'dog'} }

        it 'includes given URL parameters' do
          expect(subject).
              to eq("#{site}/big-cats/catch-mice/#{provider}?cat=dog&foo=bar")
        end
      end
    end
  end

  describe 'authorize_url' do
    let(:provider) { 'twitter' }
    subject { client.authorize_url(provider, params) }

    context 'when authorize_url option is not specified' do
      let(:options) { {:site => site} }

      context 'without URL parameters' do
        let(:params) { {} }

        it 'replaces provider in URL' do
          expect(subject).to eq("#{site}/auth/#{provider}")
        end
      end

      context 'with URL parameters' do
        let(:params) { {'foo' => 'bar', 'cat' => 'dog'} }

        it 'includes given URL parameters' do
          expect(subject).to eq("#{site}/auth/#{provider}?cat=dog&foo=bar")
        end
      end
    end

    context 'when authorize_url option is specified' do
      let(:options) {
        {:site => site, :authorize_url => '/:provider/FABULOUS-URL'}
      }

      context 'without URL parameters' do
        let(:params) { {} }

        it 'replaces provider in URL' do
          expect(subject).to eq("#{site}/#{provider}/FABULOUS-URL")
        end
      end

      context 'with URL parameters' do
        let(:params) { {'foo1' => 'bar', 'cat' => 'dog2'} }

        it 'includes given URL parameters' do
          expect(subject).
              to eq("#{site}/#{provider}/FABULOUS-URL?cat=dog2&foo1=bar")
        end
      end
    end
  end
end
