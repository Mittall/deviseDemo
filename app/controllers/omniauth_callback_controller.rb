class OmniauthCallbackController < Devise::OmniauthCallbackController

#skip_before_action :verify_authenticity_token

 def facebook
    user = User.from_omniauth(request.env["omniauth.auth"])
    if user.persisted?
      flash.notice = "Signed in Through Google!"
      sign_in_and_redirect user
    else
      session["devise.user_attributes"] = user.attributes
      flash.notice = "You are almost Done! Please provide a password to finish setting up your account"
      redirect_to new_user_registration_url
    end
  end
 
=begin
  def sign_up(resource_name, resource)
    sign_in(resource_name, resource)
    resource.password = resource_params[:password]
    resource.send_confirmation_instructions
  end
=end

end
