module CanvasOauth
  class CanvasController < CanvasOauth::ApplicationController
    skip_before_action :request_canvas_authentication

    def oauth
      redirect_path = params["redirect_to"]
      if redirect_path.include? "data"
        data = redirect_path.partition("data=").last
        data_hash = convert_string_param_to_actual_param(data).reduce({}, :merge)
        encoded_redirect_path = "/namedrop_api_call?data=name:#{data_hash["name"]},email:#{CGI.escape(data_hash["email"])},unique_id:#{data_hash["unique_id"]},org_name:#{data_hash["org_name"]}"
      else
        encoded_redirect_path = redirect_path
      end
      if verify_oauth2_state(params[:state]) && params[:code]
        if (token_details = canvas.get_access_token(params[:code]))
          access_token = token_details["access_token"]
          refresh_token = token_details["refresh_token"]
          expires_in = Time.now + token_details["expires_in"].to_i - 5.minutes
          if CanvasOauth::Authorization.cache_token(access_token, user_id, tool_consumer_instance_guid)
            redirect_to "/authorization?access_token=#{access_token}&refresh_token=#{refresh_token}&expires_in=#{expires_in}&redirect_path=#{encoded_redirect_path}"
          else
            render plain: "Error: unable to save token"
          end
        else
          render plain: "Error: invalid code - #{params[:code]}"
        end
      else
        render plain: "This application needs access to your account in order to function properly. Please try again and click log in to approve the integration."
      end
    end

    def verify_oauth2_state(callback_state)
      callback_state.present? && callback_state == session.delete(:oauth2_state)
    end
  end
end
