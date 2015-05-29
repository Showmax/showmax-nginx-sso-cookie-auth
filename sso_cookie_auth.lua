local cookie = ngx.unescape_uri(ngx.var.cookie_showmaxAuth)
local hmac = ""
local timestamp = ""
local key = "ce6chah6ongei2Soo1tiekeez4ohlu8aequeexie6oghoh0jietoosha8jeirith"

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

local back_url = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.uri .. uri_args_string()
return ngx.redirect("https://sso.showmax.cc/".."?r=".. ngx.escape_uri(ngx.encode_base64(back_url)))

