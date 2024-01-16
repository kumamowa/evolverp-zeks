PORT = 25565

json = require "json"
snet = require "snet"
bstream = snet.bstream

zeks = setmetatable({},{
	__index = function(self,k)
		if k == "save" then
			return function()
				local f = io.open("zeks.json","w")
				f:write(json.encode(self))
				f:close()
			end
		elseif k == "load" then
			return function()
				if io.open("zeks.json","r") == nil then
					local f = io.open("zeks.json","w"); f:write("{}"):close()
				end
				local f = io.open("zeks.json","r")
				self = json.decode(f:read("*a"))
				f:close()
			end
		end
	end
})
log = function(...)
	local text = "["..os.date("%H:%M:%S").."]"
	for k,v in pairs({...}) do text = text .. v .. "    " end
	local filename = "logs\\"..os.date("%d-%m-%Y")..".log"
	if io.open(filename,'r') == nil then
		local f = io.open(filename,"w"); f:write(""):close()
	end
	local f = io.open(filename,"a")
	print(text)
	f:write(text.."\n")
	f:close()
end
banlist = function(arg)
	local filename = "banlist.txt"
	if io.open(filename,'r') == nil then
		local f = io.open(filename,"w"); f:write(""):close()
	end
	local f = io.open('banlist.txt',"r")
	for l in f:read("*a"):gmatch("[^\n]+") do
		if l:lower() == arg:lower() then
			return true
		end
	end
	return false
end
zeks.load()

server = snet.server("0.0.0.0", PORT)
function enum(arr)
    for k,v in pairs(arr) do _G[v] = k end
end
enum {
	"PING",
	"PONG",
	"SENDZEK",
	"FREEZEK",
	"GETZEKS"
}

function sendAllZeks()
	for k,_ in pairs(server.clients) do
		local bs = bstream.new()
		bs:write(BS_UINT8,#zeks)
		for _,v in pairs(zeks) do
			bs:write(BS_UINT8,#v.suspect)
			bs:write(BS_STRING,v.suspect)
			bs:write(BS_UINT16,v.howLong)
			bs:write(BS_UINT8,#v.who)
			bs:write(BS_STRING,v.who)
			bs:write(BS_UINT32,v.when)
		end
		server:send(GETZEKS,bs,0,k:match("(%S+)%:"),tonumber(k:match("%:(%d+)")))
	end
end

server:add_event_handler('onReceivePacket', function(packet, bs,address,port) 
	if packet == 11 then
		print("PING",address,port,bs:read(BS_FLOAT))
	end
	if packet == 10 then
		server:send(10,bstream.new(),0,address,port)
	end
	if banlist(address..":"..port) then
		return 
	end
	if packet == PING then
		print("PING-PONG",address,port)
		server:send(PONG,bstream.new(),0,address,port)
	elseif packet == SENDZEK then
		local suspect = bs:read(BS_STRING,bs:read(BS_UINT8))
		local howLong = bs:read(BS_UINT16)
		local who = bs:read(BS_STRING,bs:read(BS_UINT8))
		local when = bs:read(BS_UINT32)
		if suspect:find("^%w+_%w+$") and who:find("^%w+_%w+$") then
			log("[ZEK APPEND]",address,port,("suspect:%s,howLong:%s,who:%s,when:%s"):format(suspect,howLong,who,when))
			if howLong == -1 then
				howLong = 1800--3600/2
			end
			table.insert(zeks,{suspect=suspect,howLong = howLong,who = who, when = when})
			sendAllZeks()
			zeks.save()
		end
	elseif packet == FREEZEK then
		local suspect = bs:read(BS_STRING,bs:read(BS_UINT8))
		for k,v in pairs(zeks) do
			if v.suspect == suspect:lower() then
				table.remove(zeks,k)
				sendAllZeks()
			end
		end
		zeks.save()
		log("[ZEK REMOVE]",address,port,("suspect:%s"):format(suspect))
	elseif packet == GETZEKS then
		sendAllZeks()
	end
end)

githubapi = {}
setmetatable(githubapi,{
    __call = function(_,token)
        return setmetatable({token=token},{
            __index = function(self,k)
                local requests = require "requests"
                local base64 = require "base64"
                if requests[k] ~= nil then
                    return function(args)
                        local headers = {
                            ['Authorization'] = 'token '..self.token,
                            ['Accept'] = 'application/vnd.github+json',
                        }
                        if args['url'] ~= nil and args['url']:find("^https%:%/%/github%.com%/%S+/%S.%S+$") then
                            args.repository = args['url']:match("https%:%/%/github%.com%/((.-)/(.-))%/")
                            args.path = args['url']:match("https%:%/%/github%.com%/.+/main/(.+)")
                        end

                        if k == "get" then
                            local r = requests.get(("https://raw.githubusercontent.com/%s/master/%s"):format(args.repository,args.path))
                            return (r.status_code==200),r
                        end
                        local r = requests.get(("https://api.github.com/repos/%s/contents/%s"):format(args.repository,args.path),{
                            ['headers']  = headers,
                        })
                        local old = json.decode(r.text)
                        if r.status_code ~= 200 then
                            old['sha'] = nil
                        end
                        local data = {
                            ['message'] = 'new commint from API',
                            ['sha'] = old['sha'],
                        }
                        if args['content'] ~= nil then
                            data['content'] = base64.encode(args.content)
                        end

                        local r = requests.put(("https://api.github.com/repos/%s/contents/%s"):format(args.repository,args.path),{
                            ['headers']  = headers,
                            ['data'] = json.encode(data) ,
                        })
                        return (r.status_code == 200),r
                    end
                end
            end
        })
    end,
})
github = githubapi("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")
github_update = os.clock()

while true do 
	server:process()

	for k,v in pairs(zeks) do
		if math.abs(os.time()-v.when) >= v.howLong then
			log("[ZEK TIMEOUT(REMOVE)]",address,port,("suspect:%s,howLong:%s,who:%s,when:%s"):format(v.suspect,v.howLong,v.who,v.when))
			table.remove(zeks,k)
			zeks.save()
			sendAllZeks()
		end

		for kk,vv in pairs(zeks) do
			if v.suspect == vv.suspect and k ~= kk then
				table.remove(zeks,(v.howLong >= vv.howLong and k or kk))
				zeks.save()
				sendAllZeks()
			end
		end
	end

	if os.clock()-github_update >= 60 and #zeks >= 1 then
		github_update = os.clock()
		local content = ""
		for k,v in pairs(zeks) do
			content = content .. string.format("%s | %s(%s) | %s | %s(%s)\n",v.suspect,v.howLong-(os.time()-v.when),v.howLong,v.who,os.date("%H:%M:%S",v.when),v.when)
		end
		local status,r = github.put({url="https://github.com/kumamowa/evolverp-zeks/blob/main/zeks.txt",content=content})
	end

end


