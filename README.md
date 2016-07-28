# ShowMax SSO cookie nginx module

This is a LUA module for `nginx` which will verify authentication cookie presented in requests. If cookie is missing or is invalid, it will send a redirect to SSO (single-sign-on) service. It is available as Debian package in our repository as `showmax-nginx-sso-cookie-auth`.

It caters for domain it is running, so no configuration is necessary. Use is thus super simple, this is example of grafana service:
```
	location / {
		access_by_lua_file /opt/showmax/nginx-sso-cookie-auth/sso_cookie_auth.lua;

		proxy_pass http://127.0.0.1:6081;
		proxy_set_header Host $http_host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto "https";
	}
```

So adding
```
		access_by_lua_file /opt/showmax/nginx-sso-cookie-auth/sso_cookie_auth.lua;
```
to your location configuration should be enough to get you protected (+ you have to install this package).

## Overriding return host

Return URL is normally taken from `nginx` and you don't need to care about it. Sometimes you need to able to override it. Especially when you are behind other proxy. You can do it with

```
           set $sso_return_url 'https://kibana.showmax.cc';
```
