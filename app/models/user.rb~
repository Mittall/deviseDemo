class User < ActiveRecord::Base

  require 'devise/encryptors/aes256'

  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable, :confirmable, :omniauthable, 
         :recoverable, :rememberable, :trackable, :validatable, :lockable, :timeoutable, :timeout_in => 1.minutes, :omniauth_providers => [:facebook]

	devise :encryptable

	def get_pass(id)
		
		@pass1 = User.find(id)
		@pass2 = @pass1.encrypted_password
		@pass = ::AES.decrypt(@pass2, Devise.pepper)
		return @pass
	end


  #attr_accessible :email, :username, :provider, :uid
  #attr_accessor :password

  def self.from_omniauth(auth)
    if user = User.find_by_email(auth.info.email)
      user.provider = auth.provider
      user.uid = auth.uid
      user
    else
      where(auth.slice(:provider, :uid)).first_or_create do |user|
        user.provider = auth.provider
        user.uid = auth.uid
        user.username = auth.info.name
        user.email = auth.info.email
      end
    end
  end
	
=begin

	def get_password
	  crypt = ActiveSupport::MessageEncryptor.new(Rails.configuration.secret_base_key)
		#encrypted_data = crypt.encrypt_and_sign(User.encrypted_password)
		decrypted_back = crypt.decrypt_and_verify(User.encrypted_password)
		return decrypted_back
	end

#

	def set_password
		@user.upassword = params[:resource][:password]
	end
	

	  before_save :encrypt_fields
    attr_accessor :password

    def password
        @decrypted_password ||= decrypt_field(:password)
    end

private

    def encrypt_fields
        write_attribute :encrypted_password, Encryption::OpenSSL_RSA.encrypt(@password)
    end

    def decrypt_field(field)
        Encryption::OpenSSL_RSA.decrypt read_attribute("encrypted_#{field}")
    end

=end
	
end
