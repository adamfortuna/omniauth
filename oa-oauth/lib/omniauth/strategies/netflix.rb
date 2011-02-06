require 'omniauth/oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    # 
    # Authenticate to Netflix via OAuth and retrieve an access token for API usage
    #
    # Usage:
    #
    #    use OmniAuth::Strategies::Netflix, 'consumerkey', 'consumersecret'
    #
    class Netflix < OmniAuth::Strategies::OAuth
      def initialize(app, consumer_key, consumer_secret)
        super(app, :netflix, consumer_key, consumer_secret,
                # :site => 'https://api.netflix.com',
                :request_token_path => "http://api.netflix.com/oauth/request_token",
                :access_token_path  => "http://api.netflix.com/oauth/access_token",
                :authorize_path     => "https://api-user.netflix.com/oauth/login")
      end
      
      
      def request_phase
        request_token = consumer.get_request_token(:oauth_callback => callback_url)
        (session[:oauth]||={})[name.to_sym] = {:callback_confirmed => request_token.callback_confirmed?, :request_token => request_token.token, :request_secret => request_token.secret}
        r = Rack::Response.new
        # For some reason, Netflix NEEDS the &oauth_consumer_key query param or the user receives an error.
        r.redirect request_token.authorize_url + "&oauth_consumer_key=" + @consumer.key
        r.finish
      end
      
      def auth_hash
        OmniAuth::Utils.deep_merge(super, {
          'uid' => @access_token.params[:user_id],
          'user_info' => user_info,
          'extra' => {'user_hash' => user_hash}
        })
      end
      
      def user_info
        user_hash = self.user_hash
        
        {
          'user_id' => user_hash['user_id'],
          'first_name' => user_hash['first_name'],
          'last_name' => user_hash['last_name']
        }
      end
      
      def user_hash
        @user_hash ||= MultiJson.decode(@access_token.get("/user/#{@access_token.params[:user_id]}").body)
      end
      
      
    end
  end
end
