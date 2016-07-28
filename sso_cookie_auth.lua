local cookie = ngx.unescape_uri(ngx.var.cookie_showmaxAuth)
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

-- Check existence of cookie
if cookie ~= nil and cookie:find(":") ~= nil then
    -- Cookie format is expiration:signature
    local divider = cookie:find(":")
    timestamp = cookie:sub(0, divider-1)
    hmac_sign = cookie:sub(divider+1)

    local sign = (hmac_sign:gsub("..", function (cc)
                    return string.char(tonumber(cc, 16))
                  end))

    if ngx.hmac_sha1(key, timestamp) == sign and tonumber(timestamp) >= ngx.time() then
      return
    end
end

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

