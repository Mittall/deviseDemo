class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
	
=begin
	#before_filter :get_password

  def get_password
		salt  = SecureRandom.random_bytes(64)
		key   = ActiveSupport::KeyGenerator.new('password').generate_key(salt)
		crypt = ActiveSupport::MessageEncryptor.new(key)
		encrypted_data = crypt.encrypt_and_sign('mittal')
		pswd = crypt.decrypt_and_verify(encrypted_data)
		return pswd
  end
=end

	@user = User.find(:all)





end
