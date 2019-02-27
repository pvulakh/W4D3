class RemoveColumnblah < ActiveRecord::Migration[5.2]
  def change
    remove_column :users, :session_token, :string
  end
end
