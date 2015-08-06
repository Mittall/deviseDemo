class UserController < ApplicationController
 
  require 'devise'
	
@@decrypted_value = ""
 
  before_action :set_user, only: [:show, :edit, :update, :destroy]

  # GET /users
  # GET /users.json
  def index
    @users = User.all
  end

  # GET /users/1
  # GET /users/1.json
  def show
  end

  # GET /users/new
  def new
    @user = User.new
  end

  # GET /users/1/edit
  def edit
  end

  # POST /users
  # POST /users.json
  def create
    @user = User.new(user_params)

    #@user.password_salt = SecureRandom.hex(25)

    #@pass = BCrypt::Password.create(params[:user][:password])

    #@user.encrypted_password = @user.password_salt + @pass

##-----------------------------------------------------------
   @user.password_salt = Time.now.to_i.to_s

    secret_key = 'secret'

		iv = OpenSSL::Cipher::Cipher.new('aes-256-cbc').random_iv
	
     @pass = params[:user][:password]

     @user.encrypted_password = Encryptor.encrypt(params[:user][:password], :key => secret_key, :iv => iv, :salt => @user.password_salt)

     @selfcreated = @user.encrypted_password

     @@decrypted_value = Encryptor.decrypt(@user.encrypted_password, :key => secret_key, :iv => iv, :salt => @user.password_salt)

##---------------------------------------------------------------

    respond_to do |format|
      if @user.save
        format.html { redirect_to @user, notice: 'User was successfully created.' }
        format.json { render action: 'show', status: :created, location: @user }
      else
        format.html { render action: 'new' }
        format.json { render json: @user.errors, status: :unprocessable_entity }
      end
    end
  end

  # PATCH/PUT /users/1
  # PATCH/PUT /users/1.json
  def update
    respond_to do |format|
      if @user.update(user_params)
        format.html { redirect_to @user, notice: 'User was successfully updated.' }
        format.json { head :no_content }
      else
        format.html { render action: 'edit' }
        format.json { render json: @user.errors, status: :unprocessable_entity }
      end
    end
  end

  # DELETE /users/1
  # DELETE /users/1.json
  def destroy
    @user.destroy
    respond_to do |format|
      format.html { redirect_to users_url }
      format.json { head :no_content }
    end
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_user
      @user = User.find(params[:id])
    end

    # Never trust parameters from the scary internet, only allow the white list through.
    def user_params
      params.require(:user).permit(:name, :email, :password, :password_salt, :encrypted_password)
    end
end
