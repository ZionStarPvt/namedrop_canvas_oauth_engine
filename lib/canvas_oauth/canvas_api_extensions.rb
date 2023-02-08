module CanvasOauth
  class CanvasApiExtensions
    def self.build(canvas_url, user_id, tool_consumer_instance_guid, app_key = "")
      key_secret_details = LtiCredential.where(lti_key: app_key).first
      key = key_secret_details.developer_key
      secret = key_secret_details.developer_secret
      token = CanvasOauth::Authorization.fetch_token(user_id, tool_consumer_instance_guid)
      CanvasApi.new(canvas_url, token, key, secret)
    end
  end
end
