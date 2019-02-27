class User < ApplicationRecord
  validates :user_name, presence: true, uniqueness: true
  validates :password_digest, presence: true

  after_initialize :ensure_session_token

  attr_reader :password 

  def self.find_by_credentials(user_name, password)
    user = User.find_by(user_name: user_name) 
    if user.nil?
      return nil
    elsif user.is_password?(password)
      return user 
    end
    nil 
  end

  def reset_session_token!
    self.update!(session_token: self.class.generate_session_token)
    self.session_token
  end

  def password=(password)
    @password = password 
    self.password_digest = BCrypt::Password.create(password) #Bcrypt is a class, Password is a sublcass (?), .create is a BCrypt::Password method that salts and hashes. 
  end

  def is_password?(password)
    bcrypt_password = BCrypt::Password.new(self.password_digest)
    bcrypt_password.is_password?(password)
  end

  private 

  def ensure_session_token
    self.session_token ||= self.class.generate_session_token
  end 

  def self.generate_session_token
    SecureRandom::urlsafe_base64
  end

end 