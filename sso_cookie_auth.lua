local cjson  = require 'cjson'

local cookie_auth_data = ngx.unescape_uri(ngx.var.cookie_showmaxAuthData)
local cookie_auth_sign = ngx.unescape_uri(ngx.var.cookie_showmaxAuthSign)
local hmac = ""
local timestamp = ""

local keys = {}
keys["cc"]  = "ce6chah6ongei2Soo1tiekeez4ohlu8aequeexie6oghoh0jietoosha8jeirith"
keys["io"]  = "ooghahPheraiYesozaPae1shuo7eezoabuafahvaicaveeW7aiTei2Haewahvaic"
keys["com"] = "aicoh5eethoovieD9eiXie0oY0loomaerueL5Pae5Eayilai5aeQu2IYahx6jifu"

local key = ""
local sso_url = ""

local sso_domain_match = ngx.re.match(ngx.var.host, "showmax.(cc|io|com)")
if sso_domain_match then
  sso_url = "https://sso." .. sso_domain_match[0]
  key = keys[sso_domain_match[1]]
else
  ngx.log(ngx.ERR, "Unknown SSO domain: " .. ngx.var.host)
  ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
  ngx.say("500 - Server misconfigured - see error log")
  return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
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
          ngx.req.set_header("showmax-int-Auth-Uid", auth_data['uid'])
        end
        return
      end
    end
end

-- Being here means, that your signature was invalid/expired/missing
-- and you should be redirected to SSO

-- Convert a table of arguments to an URI string
function uri_args_string (args)
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
if ngx.var.sso_return_url ~= nil then
 back_url = ngx.var.sso_return_url
end
back_url = back_url .. ngx.var.uri .. uri_args_string()

return ngx.redirect(sso_url .. "/?r=".. ngx.escape_uri(ngx.encode_base64(back_url)))

