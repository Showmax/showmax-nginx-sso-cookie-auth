# Showmax SSO cookie nginx module

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

## Require certain audience

Part of the authentication data is also audience. For list of values, please check the [SSO project](https://git.showmax.cc/ops/ops-sso).

```
           set $sso_allowed_audience 'showmax';
```

Will require to have ShowMax account to get access. You don't need to specify this though as it is default value. So you don't need to change anything in your configuration if it is in front of internal service.

If you don't care for audience (aka looking for valid account only) use ``any`` as value:

```
           set $sso_allowed_audience 'any';
```

You can also specify multiple values. They are treated as having **OR** between then. So for example

```
           set $sso_allowed_audience 'showmax, recombee';
```

Will give access to account which is either in ``showmax``, or in ``recombee`` or both (first match will win anyway).

Note: I was thinking (and initially implemented AND option). But it turned out, that OR would be more useful, at least for now. We can add it later with e.g. ``sso_required_audience`` option.

## Authentication data
We are now passing authentication cookie `Showmax-Auth-Data` which contains JSON with additional data. You can find description of the fields in https://git.showmax.cc/ops/ops-sso project. Some of data are copied for convenience into request headers. Those are:

  * `X-Forwarded-User` == `uid`

