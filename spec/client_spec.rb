RSpec.describe Oauthio::Client do
  let(:site) { 'https://oauth.io' }
  subject { Oauthio::Client.new('123', '53cr37', options) }

  describe 'me_url' do
    context 'when me_url option is not specified' do
      let(:options) { {:site => site} }

      it 'replaces provider in URL' do
        expect(subject.me_url('google')).to eq("#{site}/auth/google/me")
      end

      it 'includes given URL parameters' do
        expect(subject.me_url('twitter', {'foo' => 'bar', 'cat' => 'dog'})).
            to eq("#{site}/auth/twitter/me?cat=dog&foo=bar")
      end
    end

    context 'when me_url option is specified' do
      let(:options) {
        {:site => site, :me_url => '/big-cats/catch-mice/:provider'}
      }

      it 'replaces provider in URL' do
        expect(subject.me_url('twitter')).
            to eq("#{site}/big-cats/catch-mice/twitter")
      end

      it 'includes given URL parameters' do
        expect(subject.me_url('facebook', {'foo' => 'bar', 'cat' => 'dog'})).
            to eq("#{site}/big-cats/catch-mice/facebook?cat=dog&foo=bar")
      end
    end
  end
end
