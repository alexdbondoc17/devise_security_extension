# After each sign in, create new traceable session.
# This is only triggered when the user is explicitly set (with set_user)
# and on authentication. Retrieving the user from session (:fetch) does
# not trigger it.
Warden::Manager.after_set_user except: :fetch do |record, warden, options|
  scope = options[:scope]
  if record.respond_to?(:log_traceable_request!) && warden.authenticated?(options[:scope])
    opts = {}
    opts[:ip_address] = warden.request.remote_ip
    opts[:user_agent] = warden.request.env['HTTP_USER_AGENT']
    opts[:app_domain] = warden.request.domain
    opts[:app_subdomain] = warden.request.subdomain
    unique_auth_token_id = record.log_traceable_request!(opts)
    if unique_auth_token_id
      warden.session(options[:scope])['unique_auth_token_id'] = unique_auth_token_id
    else
      warden.logout(scope)
      throw :warden, :scope => scope, :message => :unauthenticated
    end
  end
end

# Each time a record is fetched from session we verify if the session
# has a valid unique session identifier.
# If so, the session we set the last accessed time.
Warden::Manager.after_set_user only: :fetch do |record, warden, options|
  scope = options[:scope]
  session =  warden.session(scope)
  if record.respond_to?(:accept_traceable_token?) && warden.authenticated?(scope) && options[:store] != false
    opts = { ip_address: warden.request.remote_ip }
    if session['unique_auth_token_id'].present? && record.accept_traceable_token?(session['unique_auth_token_id'], opts)
      record.update_traceable_token(session['unique_auth_token_id'])
    else
      warden.logout(scope)
      throw :warden, :scope => scope, :message => :unauthenticated
    end
  end
end

# Before each sign out, we expire the session.
Warden::Manager.before_logout do |record, warden, options|
  session =  warden.request.session["warden.user.#{options[:scope]}.session"]
  if record && record.respond_to?(:expire_session_token) && session && session['unique_auth_token_id'].present?
    record.expire_session_token(session['unique_auth_token_id'])
    session.delete 'unique_auth_token_id'
  end
end