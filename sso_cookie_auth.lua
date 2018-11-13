local cjson  = require 'cjson'

local cookie_auth_data = ngx.unescape_uri(ngx.var.cookie_FIXME_YOUR_AUTH_DATA_COOKIE)
local cookie_auth_sign = ngx.unescape_uri(ngx.var.cookie_FIXME_YOUR_AUTH_SIGN_COOKIE)
local hmac = ""
local timestamp = ""

local keys = {}

local key = ""
local sso_url = ""

local sso_domain_match = ngx.re.match(ngx.var.host, "FIXME_ALLOWED_DOMAINS_REGEX")
if sso_domain_match then
  sso_url = "https://sso." .. sso_domain_match[0]
  key = keys[sso_domain_match[0]]
  if key == nil then
    ngx.log(ngx.ERR, "Unable to fetch key for: " .. sso_domain_match[0])
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
else
  ngx.log(ngx.ERR, "Unknown SSO domain: " .. ngx.var.host)
  ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
  return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local function validate_allowed_audience(allowed_audiences, present_audiences)
  if allowed_audiences == '' then return true end
  for allowed_audience in string.gmatch(allowed_audiences, '([^, ]+)') do
    for _, audience in ipairs(present_audiences) do
      if allowed_audience == audience then return true end
    end
  end
  return false
end

-- Verify signature
if cookie_auth_data ~= nil and cookie_auth_sign ~= nil then
    local sign = (cookie_auth_sign:gsub("..", function (cc)
                    return string.char(tonumber(cc, 16))
                  end))

    if ngx.hmac_sha1(key, cookie_auth_data) == sign then
      local auth_data = cjson.decode(ngx.decode_base64(cookie_auth_data))
      -- Verify validity of signature
      if tonumber(auth_data['exp']) >= ngx.time() then
        if auth_data['uid'] ~= cjson.null then
          ngx.req.set_header("X-Forwarded-User", auth_data['uid'])
        end

        -- Sanitize required audience
        sso_allowed_audience = 'nobody'
        if ngx.var.sso_allowed_audience ~= nil and ngx.var.sso_allowed_audience ~= '' then
          if ngx.var.sso_allowed_audience == 'any' then
            sso_allowed_audience = ''
          else
            sso_allowed_audience = ngx.var.sso_allowed_audience
          end
        end

        -- Verify if the user has appropriate audience
        if not validate_allowed_audience(sso_allowed_audience, auth_data['aud']) then
          ngx.log(ngx.ERR, "User " .. auth_data['uid'] .. "doesn't have any of allowed audiences.")
          ngx.status = ngx.HTTP_FORBIDDEN
          return ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        -- We have validated auth cookie and passing the request
        ngx.req.set_header("X-Forwarded-Audiences", auth_data['aud'])
        return
      end
    end
end

-- Being here means, that your signature was invalid/expired/missing
-- and you should be redirected to SSO

-- Convert a table of arguments to an URI string
local function uri_args_string (args)
    if not args then
        args = ngx.req.get_uri_args()
    end
    String = "?"
    for k,v in pairs(args) do
        String = String..tostring(k).."="..tostring(v).."&"
    end
    return string.sub(String, 1, string.len(String) - 1)
end

local back_url = ngx.var.scheme .. "://" .. ngx.var.host
if ngx.var.sso_return_url ~= nil and ngx.var.sso_return_url ~= '' then
 back_url = ngx.var.sso_return_url
end
back_url = back_url .. ngx.var.uri .. uri_args_string()

local accept = ngx.req.get_headers()["accept"]
if accept ~= nil and string.match(accept, "image/") then
  local image = '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'
  ngx.header.content_type = "image/svg+xml"
  ngx.header.content_encoding = "gzip"
  ngx.print(ngx.decode_base64(image))
  ngx.exit(ngx.HTTP_OK)
end

return ngx.redirect(sso_url .. "/?r=".. ngx.escape_uri(ngx.encode_base64(back_url)))

