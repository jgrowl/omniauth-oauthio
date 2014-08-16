RSpec.describe Oauthio::Client do
  let(:site) { 'https://oauth.io' }
  subject { Oauthio::Client.new('123', '53cr37', {:site => site}) }

  describe 'me_url' do
    it 'replaces provider in URL' do
      expect(subject.me_url('google')).to eq("#{site}/auth/google/me")
    end

    it 'includes given URL parameters' do
      expect(subject.me_url('twitter', {'foo' => 'bar', 'cat' => 'dog'})).
          to eq("#{site}/auth/twitter/me?cat=dog&foo=bar")
    end
  end
end
