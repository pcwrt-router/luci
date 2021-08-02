local http = require "luci.http"
local util = require "luci.util"
local uci = require "luci.pcuci"
local status = require "luci.tools.status"
local jsonc = require "luci.jsonc"
local dt = require "luci.cbi.datatypes"
local i18n = require "luci.i18n"
require "luci.pcutil"

module("luci.pccontroller.settings.network", package.seeall)

ordering = 20
display_name  = i18n.translate('Network')

local network = 'network'
local dhcp = 'dhcp'
local firewall = 'firewall'
local lan = 'lan'

local function get_config_hosts(c)
    local hosts = {}
    c:foreach(dhcp, 'host', function(s)
 	for _, mac in ipairs(s.mac:split(' ')) do
  	    hosts[#hosts+1] = {
   		name = s.name,
    		mac = mac:upper(),
     		ip = s.ip,
      	    }
       	end
    end)
    return hosts
end

local function flattern_hosts(updt_vals)
    local hosts = {}
    for _, v in ipairs(updt_vals) do
     	local found = nil
      	for _, h in ipairs(hosts) do
	    if v.name:upper() == h.name:upper() then
		found = h
	 	break
	    end
	end

	if found then
	    found.mac = found.mac .. ' ' .. v.mac
	else
	    hosts[#hosts+1] = {
	  	name = v.name,
	   	mac = v.mac,
	    	ip = v.ip,
	    }
	end
    end

    return hosts
end

local function get_config_routes(c)
    local routes = {}
    c:foreach(network, 'route', function(s)
	routes[#routes+1] = {
	    interface = s.interface,
	    target = s.target,
	    netmask = s.netmask,
	    gateway = s.gateway,
	    metric = s.metric,
	}
    end)
    return routes
end

local function get_config_forwards(c)
    local forwards = {}
    c:foreach(firewall, 'redirect', function(s)
	if s.target == 'DNAT' and s.src == 'wan' and
	   (s.enabled == nil or s.enabled == '1') then
	    forwards[#forwards+1] = {
		name = s.name,
		proto = s.proto,
		src_dport = s.src_dport,
		dest_ip = s.dest_ip,
		dest_port = s.dest_port,
	    }
	end
    end)
    return forwards
end

local function update_config(c, cfgs, config, cfg_type, del_cmp, exist_vals, updt_vals, cmp)
    local change = false
    if #updt_vals ~= #exist_vals then
	change = true
    else
	for _, v1 in ipairs(exist_vals) do
	    for i, v2 in ipairs(updt_vals) do
		if cmp(v1, v2) then
		    v1.no_change = true
		    break
		end
	    end
	end

	for _, v1 in ipairs(exist_vals) do
	    if not v1.no_change then
		change = true
		break
	    end
	end
    end

    if change then
	local del = {}
	c:foreach(config, cfg_type, function(r)
	    if not del_cmp or del_cmp(r) then
		del[#del+1] = r['.name']
		-- For WAN port forwarding, remove ACCEPT rule --
		if config == firewall and cfg_type == 'redirect' then
		    c:foreach(firewall, 'rule', function(r2)
			if r2.name == r.name and
			    r2.target == 'ACCEPT' and
			    r2.src == r.src and
			    r2.proto == r.proto and
			    r2.dest_port == r.src_dport then
			    del[#del+1] = r2['.name']
			    return false
			end
		    end)
		end
		-- END For WAN port forwarding, remove ACCEPT rule --
	    end
	end)

	for _, j in ipairs(del) do
	    c:delete(config, j)
	end

	if #updt_vals > 0 then
   	    if cfg_type == 'host' then
  		updt_vals = flattern_hosts(updt_vals)
 	    end
	
	    for _, vals in ipairs(updt_vals) do
		c:section(config, cfg_type, nil, vals)
	    end
	end
	add_if_not_exists(cfgs, config == network and 'network' or config)
    end

    return change
end

local function get_stealth_mode(c)
    local stealth = '0'
    c:foreach(firewall, 'zone', function(s)
	if s.name == 'wan' then
	    if s.input == 'DROP' then
		stealth = '1'
	    end
	    return false
	end
    end)
    return stealth
end

local function set_stealth_mode(c, stealth_mode)
    local target = stealth_mode == '1' and 'DROP' or 'REJECT'
    c:foreach(firewall, 'zone', function(s)
	if s.name == 'wan' then
	    c:set(firewall, s['.name'], 'input', target)
	    c:set(firewall, s['.name'], 'forward', target)
	    return false
	end
    end)
end

local function get_block_ping(c)
    local bp = '0'
    c:foreach(firewall, 'rule', function(s)
	if s.name == 'Allow-Ping' then
	    if s.target == 'DROP' then
		bp = '1'
	    end
	    return false
	end
    end)
    return bp
end

local function set_block_ping(c, block_ping)
    local target = block_ping == '1' and 'DROP' or 'ACCEPT'
    c:foreach(firewall, 'rule', function(s)
	if s.name == 'Allow-Ping' then
	    c:set(firewall, s['.name'], 'target', target)
	    return false
	end
    end)
end

local function get_bridge_ifaces(c)
    local ifaces = {}
    c:foreach(network, 'interface', function(v)
	if v.type == 'bridge' then
	    ifaces[#ifaces + 1] = {
		name = v['.name'],
		ipaddr = v.ipaddr,
		netmask = v.netmask,
	    }
	end
    end)
    return ifaces
end

local function get_vlan_iface_for_ip(c, ifaces, ip)
    for _, iface in ipairs(ifaces) do
	if is_ip_in_network(ip, iface.name, c) then
	    return iface
	end
    end
    return nil
end

local function get_vlans(c)
    local tagged
    local vlans = {}
    local vlan_ports = {}
    local port_names = {}
    if c:get_first(network, 'switch_vlan') then
	c:foreach(network, 'switch_vlan', function(v)
	    if v.vlan ~= '2' and v.ports ~= nil then
		local ports = v.ports:split(' ')
		tagged = table.remove(ports)
		for _, port in ipairs(ports) do
		    vlan_ports[port] = get_canonical_vlan_id(c, v.vlan)
		    port_names[#port_names+1] = port
		end
	    end
	end)
    else
	c:foreach(network, 'interface', function(v)
	    if v.ifname then
		for _, ifname in ipairs(v.ifname:split(' ')) do
		    local ptnm = string.match(ifname, 'lan(%d)')
		    if ptnm then
			local p = get_vlan_params(v['.name'])
			if p then
			    vlan_ports[tostring(ptnm - 1)] = p.id
			    port_names[#port_names+1] = tostring(ptnm - 1)
			end
		    end
		end
	    end
	end)
    end

    vlans.options = get_vlan_options()
    vlans.ports = {}

    table.sort(port_names)
    for _, pn in ipairs(port_names) do
	vlans.ports[#vlans.ports+1] = {
	    port = pn,
	    id = vlan_ports[pn],
	}
    end

    return vlans, tagged
end

local function update_switch_vlan(c, lan_ports, vlan_ports, tagged)
    local vlan_name
    c:delete_all(network, 'switch_vlan', function(s)
	return s.vlan ~= '2'
    end)

    if #lan_ports > 0 then
	vlan_name = c:section(network, 'switch_vlan')
	c:set(network, vlan_name, 'device', 'switch0')
	c:set(network, vlan_name, 'vlan', '1')
	c:set(network, vlan_name, 'ports', table.concat(lan_ports, ' ') .. ' ' .. tagged)
    end

    local evlan_id = 0 -- effective vlan_id
    for i = 3, 6 do -- vlans have id from 3 to 6, LAN has id 1
	local vlan_id = tostring(i)
	if vlan_ports[vlan_id] ~= nil then
	    vlan_name = c:section(network, 'switch_vlan')
	    c:set(network, vlan_name, 'device', 'switch0')
	    c:set(network, vlan_name, 'vlan', tostring(evlan_id + 3))
	    c:set(network, vlan_name, 'ports', table.concat(vlan_ports[vlan_id], ' ') .. ' ' .. tagged)
	    set_effective_vlan_id(vlan_id, tostring(evlan_id + 3))
	    evlan_id = evlan_id + 1
	end
    end
end

local function validate(v)
    local errs = {}

    if not dt.ip4addr(v.ipaddr) then
	errs.ipaddr = i18n.translate('Invalid IP address')
    end

    if not dt.ip4addr(v.netmask) then
	errs.netmask = i18n.translate('Invalid netmask')
    end

    if v.start == nil or not v.start:match('^%d+$')  then
	errs.start = i18n.translate('Invalid value for DHCP Start')
    end

    if v.limit == nil or not v.limit:match('^%d+$')  then
	errs.limit = i18n.translate('Invalid value for DHCP Limit')
    end

    if v.leasetime == nil or not v.leasetime:match('^%d+[h,m]$')  then
	errs.leasetime = i18n.translate('Invalid value for DHCP Lease Time')
    end

    local ok = true
    for _, v in pairs(errs) do
	ok = false
	break
    end

    return ok, errs
end

function _get_data(c)
    return {
	ipaddr = c:get(network, lan, 'ipaddr'),
	netmask = c:get(network, lan, 'netmask'),
	start = c:get(dhcp, lan, 'start'),
	limit = c:get(dhcp, lan, 'limit'),
	leasetime = c:get(dhcp, lan, 'leasetime'),
	ifaces = get_bridge_ifaces(c),
	routes = get_config_routes(c),
	hosts = get_config_hosts(c),
	forwards = get_config_forwards(c),
	leases = status.dhcp_leases(),
	stealth_mode = get_stealth_mode(c),
	block_ping = get_block_ping(c),
	vlans = get_vlans(c),
    }
end

function index()
    local c = uci.cursor()

    local t = template("settings/network")
    local ok, err = util.copcall(t.target, t, {
	title = 'Network',
	form_value_json = jsonc.stringify(_get_data(c)),
	page_script = 'settings/network.js',
    })
    assert(ok, 'Failed to render template ' .. t.view .. ': ' .. tostring(err))
end

local function update_dhcp_option6(c, dhcp, oldip, newip)
    c:foreach(dhcp, 'dhcp', function(s)
	local opts = s.dhcp_option
	if type(opts) == 'table' then
	    local new_opts = {}
	    for _, opt in ipairs(opts) do
		if opt == '6,'..oldip then
		    new_opts[#new_opts + 1] = '6,'..newip
		else
		    new_opts[#new_opts + 1] = opt
		end
	    end
	    c:set_list(dhcp, s['.name'], 'dhcp_option', new_opts)
	end
    end)
end

function _update(c, v)
    local reboot = false
    local ok, errs = validate(v)
    if not ok then
	return {
	    status = 'error',
	    message = errs
	}
    end

    local lanip = c:get(network, lan, 'ipaddr')
    local ifaces = get_bridge_ifaces(c)

    local cfgs = {}
    local nt_cfgs = {'ipaddr', 'netmask'}
    for _, cfg in ipairs(nt_cfgs) do
	if v[cfg] ~= c:get(network, lan, cfg) then
	    c:set(network, lan, cfg, v[cfg])
	    add_if_not_exists(cfgs, 'network')
	end
    end

    if #cfgs > 0 then -- ipaddr or netmask updated, update /etc/config/mp
	reboot = true
	local mplists = {'vpnlist', 'pclist'} -- vpnlist no longer needed since UDP is proxied
	for _, mpl in ipairs(mplists) do
	    local l = c:get_list(mp, mpl, 'ip')
	    if #l > 0 then
		local l2 = {}
		for _, ip in ipairs(l) do
		    l2[#l2+1] = get_new_ip(v['ipaddr'], v['netmask'], ip)
		end
		c:set_list(mp, mpl, 'ip', l2)
		add_if_not_exists(cfgs, mp)
	    end
	end
	update_dhcp_option6(c, dhcp, lanip, v['ipaddr'])
	add_if_not_exists(cfgs, dhcp)

	-- update lanip in firewall config
	if lanip ~= v['ipaddr'] then
	    update_firewall_lan_ipset(c, lanip, false)
	    add_if_not_exists(cfgs, firewall)
	end
    end

    local dhcp_cfgs = {'start', 'limit', 'leasetime'}
    for _, cfg in ipairs(dhcp_cfgs) do
	if v[cfg] ~= c:get(dhcp, lan, cfg) then
	    c:set(dhcp, lan, cfg, v[cfg])
	    add_if_not_exists(cfgs, dhcp)
	end
    end

    -- preprocess forwards
    local forwards = v.forwards == nil and {} or jsonc.parse(v.forwards)
    for _, f in ipairs(forwards) do
	f.target = 'DNAT'
	f.src = 'wan'
	local iface = get_vlan_iface_for_ip(c, ifaces, f.dest_ip)
	f.dest = iface and iface.name or nil
    end

    -- process vlans
    local vlan_id
    local vlan_ports = {}
    local lan_ports = {}
    local vlans, tagged = get_vlans(c)
    local vlan_updated = false

    local vvlans = jsonc.parse(v.vlans);
    for _, vlan in ipairs(vvlans) do
	if vlan.id == '1' then
	    lan_ports[#lan_ports+1] = vlan.port
	else
	    local vports = vlan_ports[vlan.id]
	    if vports == nil then
		vlan_ports[vlan.id] = {vlan.port}
	    else
		vports[#vports + 1] = vlan.port
	    end
	end

	if not vlan_updated then
	    for _, vl in ipairs(vlans.ports) do
		if vl.port == vlan.port and vl.id ~= vlan.id then
		    vlan_updated = true
		    break
		end
	    end
	end
    end

    local deleted_vlan = {}
    if vlan_updated then
	if tagged then
	    update_switch_vlan(c, lan_ports, vlan_ports, tagged)
	end

	for i = 3, 6 do -- vlans have id from 3 to 6, LAN has id 1
	    vlan_id = tostring(i)
	    local nw_name = get_vlan_network_name(vlan_id)
	    if vlan_ports[vlan_id] == nil then
		if delete_vlan_network(c, nw_name, true, cfgs) then
		    deleted_vlan[nw_name] = vlan_id
		end
	    else
		create_vlan_network(c, nw_name, true, cfgs)
		if tagged then
		    local ifname = get_vlan_ifname(c, nw_name)
		    if ifname then c:set(network, nw_name, 'ifname', ifname) end
		else
		    local pn = {}
		    for _, port in ipairs(vlan_ports[vlan_id]) do
			pn[#pn+1] = 'lan'..(port + 1)
		    end
		    c:set(network, nw_name, 'ifname', table.concat(pn, ' '))
		end
	    end
	end

	if #lan_ports > 0 then
	    if tagged then
		c:set(network, lan, 'ifname', get_lan_ifname(c))
	    else
		local pn = {}
		for _, port in ipairs(lan_ports) do
		    pn[#pn+1] = 'lan'..(port + 1)
		end
		c:set(network, lan, 'ifname', table.concat(pn, ' '))
	    end
	else
	    c:delete(network, lan, 'ifname')
	end

	add_if_not_exists(cfgs, 'network')
	ifaces = get_bridge_ifaces(c)
    end

    -- process routes
    local routes = v.routes == nil and {} or jsonc.parse(v.routes)
    update_config(c, cfgs, network, 'route', nil, get_config_routes(c), routes, 
	function(r1, r2)
	    return r1.interface == r2.interface 
	       and r1.target == r2.target
	       and r1.netmask == r2.netmask
	       and r1.gateway == r2.gateway
	       and r1.metric == r2.metric
	end
    )

    -- process hosts
    local new_hosts = {}
    local hosts = v.hosts == nil and {} or jsonc.parse(v.hosts)
    for _, h in ipairs(hosts) do
	local iface = get_vlan_iface_for_ip(c, ifaces, h.ip)
	if iface and deleted_vlan[iface.name] == nil then
	    new_hosts[#new_hosts+1] = h
	end
    end

    local hosts_updated = update_config(c, cfgs, dhcp, 'host', nil, get_config_hosts(c), new_hosts,
	function(h1, h2)
	    return h1.name == h2.name and h1.mac == h2.mac and h1.ip == h2.ip
	end
    )

    -- process forwards
    local add_forwards = {}
    for _, f in ipairs(forwards) do
	if f.dest ~= nil and (f.dest == 'lan' or deleted_vlan[f.dest] == nil) then
	    add_forwards[#add_forwards+1] = f
	end
    end

    update_config(c, cfgs, firewall, 'redirect',
	function(section)
	    return section.target == 'DNAT' and
		   section.src == 'wan'
	end,
	get_config_forwards(c),
	add_forwards,
	function(f1, f2)
	    return f1.name == f2.name
	       and f1.proto == f2.proto
	       and f1.src_dport == f2.src_dport
	       and f1.dest_ip == f2.dest_ip
	       and f1.dest_port == f2.dest_port
	end
    )

    -- process security flags
    if v.stealth_mode ~= get_stealth_mode(c) then
	set_stealth_mode(c, v.stealth_mode)
	add_if_not_exists(cfgs, firewall)
    end

    if v.block_ping ~= get_block_ping(c) then
	set_block_ping(c, v.block_ping)
	add_if_not_exists(cfgs, firewall)
    end

    local success = true
    for _, cfg in ipairs(cfgs) do
	if cfg == 'network' then cfg = network end
	if not c:commit(cfg) then
	    success = false
	    break
	end
    end

    return {
	status = success and 'success' or 'fail',
    	message = success and '' or i18n.translate('Failed to save configuration'),
	apply = success and cfgs or '',
	reboot = reboot,
	reload_url = build_url and build_url('applyreboot') or '',
	addr = v['ipaddr'],
	ifaces = ifaces,
    }
end

function update()
    http.prepare_content('application/json')
    local c = uci.cursor()
    local v = http.formvalue()
    local r = _update(c, v)
    if r.status == 'success' then
	if r.reboot then
	    put_command({type="reboot"})
	elseif #r.apply > 0 then
	    local reloads = get_reload_list(c, r.apply)
	    r.apply = nil
	    put_command({
		type = "fork_exec",
		command = "sleep 3;/sbin/luci-restart %s >/dev/null 2>&1" % table.concat(reloads, ' '),
	    })
	else
	    r.apply = ''
	end
    end

    http.write_json(r)
end

function _change_hostname(c, v)
    local ok, message
    local errs = {}
    if not dt.hostname(v.hostname) then
	errs.hostname = i18n.translate('Invalid hostname')
	return {
	    status = 'error',
	    message = errs,
	}
    end

    if not dt.macaddr(v.mac) or not dt.ipaddr(v.ip) then
	return {
	    status = 'fail',
	    mac = v.mac,
	    ip = v.ip,
	    message = i18n.translate('Failed to update hostname'),
	}
    end

    local hosts = {}
    local macs = {}
    c:foreach(dhcp, 'host', function(s)
       local hostname = s.name:upper()
       for _, mac in ipairs(s.mac:split(' ')) do
 	    mac = mac:upper()
  	    if hosts[hostname] == nil then
   		hosts[hostname] = {{
    		    cfgname = s['.name'],
     		    name = s.name,
      		    flat_mac = s.mac,
       		    mac = mac,
		    ip = s.ip,
	 	}}
	    else
	   	local idx = #hosts[hostname] + 1
	    	hosts[hostname][idx] = {
	     	    cfgname = s['.name'],
	      	    mac = mac,
	       	    ip = s.ip,
		}
	    end
	    macs[mac] = {
	     	cfgname = s['.name'],
	    }
	end
    end)

    local host = hosts[v.hostname:upper()]
    if host ~= nil then
     	for _, h in ipairs(host) do
    	    if h.mac == v.mac:upper() then
   		return { status = 'success' }
  	    end
 	end
    end

    local cfgs = { dhcp }

    ok = true
    v.mac = v.mac:upper()
    local mac = macs[v.mac]
    local new_hosts = get_config_hosts(c)
    if host ~= nil then
	ok = c:set(dhcp, host[1].cfgname, 'mac', host[1].flat_mac .. ' ' .. v.mac)

  	if ok then
	    ok = c:set(dhcp, host[1].cfgname, 'ip', v.ip)
    	end

     	if ok and mac then
	    local rmac = c:get(dhcp, mac.cfgname, 'mac'):upper()
	    rmac = rmac:gsub(v.mac .. ' *', ''):trim()
	    if #rmac == 0 then
		ok = c:delete(dhcp, mac.cfgname)
	    else
		ok = c:set(dhcp, mac.cfgname, 'mac', rmac)
	    end
       	end

	local existing_mac = false
	for _, h in ipairs(new_hosts) do
	    if h.mac == v.mac then
		existing_mac = true
		h.name = v.hostname
		h.ip = v.ip
		break
	    end
	end

	if not existing_mac then
	    new_hosts[#new_hosts + 1] = {
		name = v.hostname,
		mac = v.mac,
		ip = v.ip,
	    }
	end
    else
	if mac then
	    for _, h in ipairs(new_hosts) do
		if h.mac == v.mac then
		    h.name = v.hostname
		    h.ip = v.ip
		    break
		end
	    end
	    ok = c:set(dhcp, mac.cfgname, 'name', v.hostname)
	    if ok then
		ok = c:set(dhcp, mac.cfgname, 'ip', v.ip)
	    end
	else
	    local cfgname
	    ok = c:add(dhcp, 'host')
	    if ok then
		cfgname = ok
		ok = c:set(dhcp, cfgname, 'mac', v.mac)
	    end

	    if ok then
		ok = c:set(dhcp, cfgname, 'name', v.hostname) 
	    end

	    if ok then
		ok = c:set(dhcp, cfgname, 'ip', v.ip) 
	    end
	    
	    if ok then
		new_hosts[#new_hosts + 1] = {
		    name = v.hostname,
		    mac = v.mac,
		    ip = v.ip,
		}
	    end
	end
    end

    if ok then
	table.foreach(cfgs, function(_, cfg)
	    if cfg == 'network' then cfg = network end
	    if not c:commit(cfg) then
		ok = false
		return false
	    end
	end)
    end

    return {
    	status = ok and 'success' or 'fail',
    	message = ok and '' or i18n.translate('Failed to change hostname'),
	apply = ok and cfgs or '',
    }
end

function change_hostname()
    http.prepare_content('application/json')

    local v = http.formvalue()
    local c = uci.cursor()
    local r = _change_hostname(c, v)
    http.write_json(r)
end

function ip_status() 
    http.prepare_content('application/json')

    local resp = {}
    
    local v = http.formvalue()
    if type(v.ip) == 'string' then
	v.ip = {v.ip}
    end

    for _, v in ipairs(v.ip) do
	resp[v] = os.execute("ping -c 1 -W 1 %q >/dev/null 2>&1" % v) == 0 and 'on' or 'off'
    end

    http.write_json({
	status = 'success',
	ip_status = resp,
    })
end
