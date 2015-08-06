class UserMailer < Devise::Mailer
  
  default :from => "mittalvi89@gmail.com"

  def headers_for(action, opts)
    headers = {
     :subject       => "Conformation Mail",
     :from          => Devise.mailer_sender,
     :to            => resource.email,
     :template_path => template_paths
  }.merge(opts)
  end

   #def self.mailer_name
    #"devise/mailer"
   #end

end
