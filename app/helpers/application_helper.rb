require 'openssl'
require 'base64'

module ApplicationHelper

  # class OpenSSL_Key
        PUBLIC_KEY_FILE = "#{Rails.root}/config/public.pem"
        PRIVATE_KEY_FILE = "#{Rails.root}/config/private.pem"

        def encrypt(data)
            @@public_key ||= OpenSSL::PKey::RSA.new(File.read(PUBLIC_KEY_FILE))
            encrypted_data = @@public_key.public_encrypt(data)
            Base64.encode64(encrypted_data)
        end

        def decrypt(data)
            @@private_key ||= OpenSSL::PKey::RSA.new(File.read(PRIVATE_KEY_FILE))
            decoded_data = Base64.decode64(data)
            @@private_key.private_decrypt(decoded_data)
        end
   # end

    # class OpenSSL_RSA
        IV64 = "xxxxxxxxxxxxxxxxxxxxxxxxxx==\n"
        KEY64 = "xxxxxxxxxxxxxxxxxxxxxxxxxx=\n"
        CIPHER = 'aes-256-cbc'

        def encrypt(data)
            @@iv ||= Base64.decode64(IV64)
            @@key ||= Base64.decode64(KEY64)

            cipher = OpenSSL::Cipher::Cipher.new(CIPHER)
            cipher.encrypt
            cipher.key = @@key
            cipher.iv = @@iv
            encrypted_data = cipher.update(data)
            encrypted_data << cipher.final
            Base64.encode64(encrypted_data)
        end

        def decrypt(data)
            @@iv ||= Base64.decode64(IV64)
            @@key ||= Base64.decode64(KEY64)

            cipher = OpenSSL::Cipher::Cipher.new(CIPHER)
            cipher.decrypt
            cipher.key = @@key
            cipher.iv = @@iv
            decrypted_data = cipher.update(Base64.decode64(data))
            decrypted_data << cipher.final
        end
   # end

end
