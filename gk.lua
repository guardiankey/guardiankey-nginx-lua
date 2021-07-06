
-- Insert your deploy information here. You can have it at https://panel.guardiankey.io , authgroup, tab deploy
local organization_id = ""
local authgroup_id    = ""
local key = ""
local iv  = ""
local agent_id = "NGINX" -- May be anything
local service  = "Zimbra" -- May be anything

-- More information
local login_if_redirected = true
local email_domain        = "@domainxptofoobar.com"
local login_failed_string = "CAPS LOCK"
local logout_url      = "" -- leave blank if login_if_redirected = true
local logout_url_host = "" -- leave blank if login_if_redirected = true

--[[
    
   For Zimbra:
    - Copy gk.lua and sha2.lua to /etc/nginx/
    - Edit it and add the information regarding the GuardianKey integration (AuthgroupID, key...)
    - Edit nginx.conf or an included file, example sites-enabled/default, and create the reference to gk.lua, such as below
       location / {
                proxy_pass https://webmail_zimbra.../;
               header_filter_by_lua_file /etc/nginx/gk.lua;  # ADD THIS LINE
               # ...
        }
    - Restart NGINX
--]] 

local https = require("ssl.https")
-- local http = require("socket.http") -- not used now
local cjson = require("cjson")
local ltn12 = require("ltn12")
local sha = require("/etc/nginx/sha2")
local sha256 = sha.sha256
local zlib = require("zlib")
local inflate = zlib.inflate()

-- Internal
local gk_url = "https://api.guardiankey.io/v2/checkaccess" -- Keep as is!

function Create_event(client_ip,user_agent,username,useremail,login_failed)
    local event = { ["generatedTime"]  = tostring(ngx.time()), -- tostring(os.time(os.date("*t"))),
                    ["agentId"]        = agent_id,
                    ["organizationId"] = organization_id,
                    ["authGroupId"]    = authgroup_id,
                    ["service"]        = service,
                    ["clientIP"]       = client_ip,
                    ["clientReverse"]  = "",
                    ["userName"]       = username,
                    ["authMethod"]     = "",
                    ["loginFailed"]    = login_failed,
                    ["userAgent"]      = user_agent,
                    ["psychometricTyped"] = "",
                    ["psychometricImage"] = "",
                    ["event_type"]       = "Authentication",
                    ["userEmail"]        = useremail }
    return event
end

function Check_access(client_ip,user_agent,username,useremail,login_failed)
    local event_tab = Create_event(client_ip,user_agent,username,useremail,login_failed)
    local event_str = cjson.encode(event_tab)
    local hash = sha256(event_str .. key .. iv)
    local jsonmsg = { ["id"] = authgroup_id, ["message"] = event_str, ["hash"] = hash }
    local payload = cjson.encode(jsonmsg)
    -- ngx.log(ngx.STDERR,payload)
    local response_body = { }
    local res, code, response_headers, status = https.request
    { url = gk_url, method = "POST", headers = { ["Content-Type"] = "application/json",  ["Accept"] = "*/*",  ["Content-Length"] = payload:len() },
    source = ltn12.source.string(payload),
    sink = ltn12.sink.table(response_body),
    protocol = "tlsv1" }
    -- ngx.log(ngx.STDERR,table.concat(response_body))
    return cjson.decode(table.concat(response_body))
end

-- ngx.req.read_body()
local args, err = ngx.req.get_post_args()
local req_headers = ngx.req.get_headers()

if ngx.req.get_method() == 'POST' and args["loginOp"] ~= nil and args["username"] ~= nil then -- and (ngx.status == 302 or #ngx.arg[1] > 0 ) then
    local client_ip  = tostring(ngx.var.remote_addr) -- https://stackoverflow.com/questions/42140346/get-client-ip-address-with-nginx-lua
    local user_agent = req_headers['User-Agent']
    local username   = args["username"]
    local useremail  = username
    if not string.find(username,"@") then
        useremail  = username .. email_domain
    end

    local login_failed = "0"

    if login_if_redirected then
        if ngx.status ~= 302 then
            login_failed = "1"
        end
    else
        local body_content = ""
        local status1, inflated, eof = pcall(inflate,ngx.arg[1])
        if status1 then
            body_content = inflated
        else
            body_content = ngx.arg[1]
        end

        if string.find(body_content, login_failed_string) then
            login_failed = "1"
        end
    end

    local status, gk_return = pcall(Check_access,client_ip,user_agent,username,useremail,login_failed)

   if status and gk_return["response"] == "BLOCK" then
        ngx.header['Set-Cookie'] = nil
        --ngx.log(ngx.STDERR,"BLOCKED!!!!")
        -- TODO: Take cookies from the response ngx.header['Set-Cookie']
        -- req_headers['host'] = logout_url_host
        -- req_headers['content-length'] = 0
        -- local response_body2 = { }
        -- local r, c, h, s = https.request{
        --     method = "GET",
        --     url =  logout_url,
        --     sink = ltn12.sink.table(response_body2),
        --     headers = req_headers,
        --     protocol = "tlsv1",
        --     verify = "none",
        --     ssl_verify = false
        -- }
        -- ngx.status = 200
        -- ngx.arg[1] = response_body2
    end
end

--[[
References:
    - https://github.com/openresty/lua-nginx-module#readme
    - https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/
--]]