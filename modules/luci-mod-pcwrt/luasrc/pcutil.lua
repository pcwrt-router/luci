MAX_CFG_SIZE = 1024*1024

function bool_equivalent(b1, b2)
    local b1n = b1 and b1 ~= '0' or false
    local b2n = b2 and b2 ~= '0' or false
    return b1n == b2n
end

function string.is_empty(s)
    return s == nil or (type(s) == 'string' and s:trim() == '')
end

function string.trim(s)
  return s:match "^%s*(.-)%s*$"
end

function string.starts(String,Start)
    if type(String) ~= 'string' then return false end
    return string.sub(String,1,string.len(Start))==Start
end

function string.ends(String,End)
    if type(String) ~= 'string' then return false end
    return End=='' or string.sub(String,-string.len(End))==End
end

function string:split(sep)
    local sep, fields = sep or ":", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

function string:split2(sep)
    local words = {}
    local pattern = string.format("([^%s]*)%s", sep, sep)
    for w in (self..sep):gmatch(pattern) do
	table.insert(words, w)
    end
    return words
end

function string:quote_apostrophe()
    return self:gsub("'", "'\"'\"'")
end

function string_in_array(s, a)
    if a == nil or type(a) ~= 'table' then
	return false
    end

    for _, v in ipairs(a) do
	if s == v then
	    return true
	end
    end

    return false
end

function remove_string_from_array(a, s)
    if a == nil or type(a) ~= 'table' then return false end

    local removed = false
    for i, v in ipairs(a) do
	if s == v then
	    table.remove(a, i)
	    removed = true
	    break
	end
    end

    return removed
end

function add_if_not_exists(tbl, entry)
    local found = false
    for i, v in ipairs(tbl) do
	if v == entry then
	    found = true
	    break
	end
    end

    if not found then
	tbl[#tbl+1] = entry
    end
end

function get_reload_list(c, cfgs)
    local util = require "luci.util"
    local reloads = {}

    local function _resolve_deps(name)
	local reload = { name }
	local deps = {}
	c:foreach('ucitrack', name, function(s)
	    if s.affects then
		for _, aff in ipairs(s.affects) do
		    deps[#deps+1] = aff
		end
	    end
	end)

	for _, dep in ipairs(deps) do
	    for _, add in ipairs(_resolve_deps(dep)) do
		reload[#reload+1] = add
	    end
	end

	return reload
    end

    if type(cfgs) == 'string' then
	cfgs = {cfgs}
    end

    for _, cfg in ipairs(cfgs) do
	for _, e in ipairs(_resolve_deps(cfg)) do
	    if not util.contains(reloads, e) then
		reloads[#reloads+1] = e
	    end
	end
    end

    return reloads
end

local function set_user_profile(conf, u, p)
    if conf.users ~= nil and conf.users[u] ~= nil then
	conf.users[u] = p
    end

    if conf.vpn_users ~= nil then
	for _, v in ipairs(conf.vpn_users) do
	    if v.name == u then
		v.profile = p
	    end
	end
    end

    if conf.mac ~= nil and conf.mac[u] ~= nil then
     	conf.mac[u] = p
    end
end

function get_freq_for_channel(channel, band)
    if band == '2.4 GHz' then
	return (2412 + (channel - 1) * 5)/1000
    else
	return (5180 + (channel - 36) * 5)/1000
    end
end

local function get_country(country)
    return country and string.upper(country) or 'US'
end

function get_full_txpower(hwtype)
    if hwtype == 'rt2860v2' or hwtype:starts('mt76') then
	return '100'
    else
	return '20'
    end
end

function get_ifaces_for_dev(c, dev)
    local ifaces = {}

    c:foreach('wireless', 'wifi-iface', function(i)
	if i.device == dev then
	    ifaces[#ifaces+1] = i
	end
    end)

    return ifaces
end

local i18n = require "luci.i18n"
function encryption_list(hwtype)
    local fs = require "nixio.fs"
    local el = {}
    el[#el+1] = { value = 'none', text = i18n.translate('No Encryption') }

    if hwtype == 'atheros' or hwtype == 'mac80211' or hwtype == 'prism2' then
	local hostapd = fs.access('/usr/sbin/hostapd')
	if hostapd then
	    el[#el+1] = { value = 'psk', text = i18n.translate('WPA-PSK') }
	    el[#el+1] = { value = 'psk2', text = i18n.translate('WPA2-PSK') }
	    el[#el+1] = { value = 'psk-mixed', text = i18n.translate('WPA-PSK/WPA2-PSK Mixed Mode') }
	    if has_ap_eap then
		el[#el+1] = { value = 'wpa', i18n.translate('WPA-EAP') }
		el[#el+1] = { value = 'wpa2', i18n.translate('WPA2-EAP')}
	    end
	end
    elseif hwtype == 'broadcom' or hwtype == 'rt2860v2' or hwtype:starts('mt76') then
	el[#el+1] = { value = 'psk', text = i18n.translate('WPA-PSK') }
	el[#el+1] = { value = 'psk2', text = i18n.translate('WPA2-PSK') }
	el[#el+1] = { value = 'psk+psk2', text = i18n.translate('WPA-PSK/WPA2-PSK Mixed Mode') }
    end
    return el
end

function cipher_list()
    local cl = {}
    cl[#cl+1] = { value = 'auto', text = i18n.translate('Auto') }
    cl[#cl+1] = { value = 'ccmp', text = i18n.translate('CCMP (AES)') }
    cl[#cl+1] = { value = 'tkip', text = i18n.translate('TKIP') }
    cl[#cl+1] = { value = 'tkip+ccmp', text = i18n.translate('TKIP and CCMP (AES)') }
    return cl
end

function get_encryption_desc(enc)
    local encryption, cipher, enc_desc

    if enc ~= nil then
	if enc:starts('psk+psk2') then
	    encryption = 'psk+psk2'
	    cipher = enc:sub(#encryption+2)
	else
	    encryption, cipher = string.match(enc, '(.-)+(.*)')
	    if encryption == nil then
		encryption = enc
	    end
	end
    end

    if encryption == 'psk2' then
	enc_desc = "WPA2-PSK"
    else 
	if encryption == 'psk' then
	    enc_desc = "WPA-PSK"
	else
	    if encryption == 'psk+psk2' or encryption == 'psk-mixed' then
		end_desc = "WPA-PSK/WPA2-PSK" 
	    end
	end
    end

    if not enc_desc then return i18n.translate("No Encryption") end

    if cipher == 'ccmp' then
	enc_desc = enc_desc .. ' - ' .. 'CCMP (AES)'
    else
	if cipher == 'tkip' then
	    enc_desc = enc_desc .. ' - ' .. 'TKIP'
	else
	    if cipher == 'tkip+ccmp' then 
		enc_desc = enc_desc .. ' - ' .. i18n.translate('TKIP and CCMP (AES)')
	    end
	end
    end

    return enc_desc
end

function translate_time_slots(v)
    local t = nil
    v = v:sub(2)
    v:gsub('[^,]+', function(c) 
	local sh, sm, eh, em = c:match('(%d+):(%d+)-(%d+):(%d+)')
	if not sh or not sm or not eh or not em then return end
	sh, sm, eh, em = tonumber(sh), tonumber(sm), tonumber(eh), tonumber(em)

	local s = ''
	if sh ~= 0 or sm ~= 0 or eh ~= 0 or em ~= 0 then
	    local sp = 'am'
	    if sh >= 12 then 
		sp = 'pm' 
		if sh > 12 then sh = sh - 12 end
	    end
	    if sh == 0 then sh = 12 end

	    local ep = 'am'
	    if eh >= 12 then
		ep = 'pm'
		if eh > 12 then 
		    eh = eh - 12 
		    if (eh == 12) then
			ep = 'am'
		    end
		end
	    end
	    if eh == 0 then eh = 12 end
	    s = string.format('%02d:%02d%s-%02d:%02d%s', sh, sm, sp, eh, em, ep)
	end

	t = t ~= nil and t ..'\n'.. s or s
    end)
    return t
end

function get_conf_timeslots(t)
    local v = {}
    t:gsub('[^\r\n]+', function(c)
	if not c then return end
	c = c:gsub('%s', '')
	local sh, sm, sp, eh, em, ep = c:match('(%d+):(%d+)(%a+)-(%d+):(%d+)(%a+)')
	if not sh or not sm or not eh or not em then return end
	sp = sp:lower()
	ep = ep:lower()
	if (sp ~= 'am' and sp~= 'pm') or (ep ~= 'am' and ep ~= 'pm') then return end

	sh, sm, eh, em = tonumber(sh), tonumber(sm), tonumber(eh), tonumber(em)
	if sp == 'am' and sh == 12 then
	    sh = 0
	end

	if sp == 'pm' and sh ~= 12 then
	    sh = sh + 12
	end

	if ep == 'am' and eh == 12 then
	    eh = em == 0 and 24 or 0
	end

	if ep == 'pm' and eh ~= 12 then
	    eh = eh + 12
	end

	v[#v+1] = string.format('%02d:%02d-%02d:%02d', sh, sm, eh, em)
    end)

    return #v == 0 and '00:00-00:00' or table.concat(v, ',')
end

function load_vpn_users()
    local vpn_users = {}

    -- load openvpn users
    local f, pf, s
    local ccd = '/etc/openvpn/ccd'
    local fs = require "nixio.fs"

    local dir = fs.dir(ccd)
    if dir then
	for f in dir do
	    pf = io.open(ccd .. '/' .. f, 'r')
	    if pf then
		s = pf:read('*all')
		pf:close()
		s = s:split(' ')
		if #s == 3 and s[1] == 'ifconfig-push' then
		    vpn_users[#vpn_users+1] = {
			name = f,
			ip = s[2],
		    }
		end
	    end
	end
    end

    local uci = require "luci.pcuci"
    local c = uci.cursor()

    -- load ipsec users
    c:foreach('ipsec', 'user', function(u)
	vpn_users[#vpn_users+1] = {
	    name = u.name,
	    ip = u.ip,
	}
    end)

    -- load WireGuard users
    c:foreach('wg', 'peer', function(u)
	vpn_users[#vpn_users+1] = {
	    name = u.name,
	    ip = u.ip,
	}
    end)

    return vpn_users
end

local function get_dns_server_list_as_string(dns)
    if dns == nil then
	return ''
    end

    local dns_str
    if type(dns) == 'table' then
	dns_str = table.concat(dns, ',')
    else
	dns_str = dns
    end

    if dns_str == ',' then
	return ''
    else
	if dns_str:ends(',') then
	    dns_str = dns_str:sub(0, #dns_str-1)
	end
	return '\ndns = ' .. dns_str
    end
end

function fork_exec(command)
	local pid = nixio.fork()
	if pid > 0 then
		return pid
	elseif pid == 0 then
		-- change to root dir
		nixio.chdir("/")

		-- patch stdin, out, err to /dev/null
		local null = nixio.open("/dev/null", "w+")
		if null then
			nixio.dup(null, nixio.stderr)
			nixio.dup(null, nixio.stdout)
			nixio.dup(null, nixio.stdin)
			if null:fileno() > 2 then
				null:close()
			end
		end

		-- replace with target command
		nixio.exec("/bin/sh", "-c", command)
	end
end

function fork_exec_wait(command)
	local pid = nixio.fork()
	if pid > 0 then
		local wpid, stat, rc = nixio.waitpid(pid)
		return rc
	elseif pid == 0 then
		-- change to root dir
		nixio.chdir("/")

		-- patch stdin, out, err to /dev/null
		local null = nixio.open("/dev/null", "w+")
		if null then
			nixio.dup(null, nixio.stderr)
			nixio.dup(null, nixio.stdout)
			nixio.dup(null, nixio.stdin)
			if null:fileno() > 2 then
				null:close()
			end
		end

		-- replace with target command
		nixio.exec("/bin/sh", "-c", command)
	end
end

function popen2(command)
    local r1, w1 = nixio.pipe()
    local r2, w2 = nixio.pipe()

    assert(w1 ~= nil and r2 ~= nil, "pipe() failed")

    pid = nixio.fork()
    assert(pid ~= nil, "fork() failed")

    if pid > 0 then
	r1:close()
	w2:close()
	return w1, r2
    elseif pid == 0 then
	w1:close()
	r2:close()
	nixio.dup(r1, nixio.stdin)
	nixio.dup(w2, nixio.stdout)
	r1:close()
	w2:close()
	nixio.exec("/bin/sh", "-c", command)
    end
end

local function find_mac_user(macs, v, newname)
    for mac, user in pairs(macs) do
	if user == v then
	    return v
	end
    end

    if type(newname) == 'table' then
	v = newname[v]

	if v == nil then
	    return nil
	end

	for mac, user in pairs(macs) do
	    if user == v then
		return v
	    end
	end
    end

    return nil
end

local function ip_in_network(ip, addr, mask)
    if type(addr) == 'string' and type(mask) == 'string' then
	addr = addr:split('.')
	mask = mask:split('.')
    end

    if type(addr) ~= 'table' or #addr ~= 4 or type(mask) ~= 'table' or #mask ~= 4 then
	return false
    end

    require "nixio"
    local bit = nixio.bit

    return 
	bit.band(addr[1], mask[1]) == bit.band(ip[1], mask[1]) and 
	bit.band(addr[2], mask[2]) == bit.band(ip[2], mask[2]) and 
	bit.band(addr[3], mask[3]) == bit.band(ip[3], mask[3]) and 
	bit.band(addr[4], mask[4]) == bit.band(ip[4], mask[4])
end

function is_ip_in_network(ip, net, c)
    if type(ip) == 'string' then
	ip = ip:split('.')
    end

    if type(ip) ~= 'table' or #ip ~= 4 then
	return false
    end

    if c == nil then
	c = get_uci_cursor()
    end

    local network = 'network'
    local addr = c:get(network, net, 'ipaddr')
    local mask = c:get(network, net, 'netmask')

    return ip_in_network(ip, addr, mask)
end

function fix_ip(ipaddr, netaddr1, netmask1, netaddr2, netmask2)
    local dt = require "luci.cbi.datatypes"
    if not dt.ip4addr(ipaddr) or not dt.ip4addr(netaddr1) or not dt.ip4addr(netmask1) or not dt.ip4addr(netaddr2) or not dt.ip4addr(netmask2) then
	return nil
    end

    require "nixio"
    local bit = nixio.bit

    local ip = ipaddr:split('.')
    local netip1 = netaddr1:split('.')
    local netmk1 = netmask1:split('.')
    local netip2 = netaddr2:split('.')
    local netmk2 = netmask2:split('.')

    for i=1,4 do netip1[i] = bit.band(netip1[i], netmk1[i]) end
    for i=1,4 do netip2[i] = bit.band(netip2[i], netmk2[i]) end
    for i=1,4 do ip[i] = bit.bxor(ip[i], netip1[i]) end
    for i=1,4 do ip[i] = bit.bxor(ip[i], netip2[i]) end

    return table.concat(ip, '.')
end

local user_ip_start = 100
local user_ip_max = 255
function get_next_ip(netaddr, netmask, usedips)
    local dt = require "luci.cbi.datatypes"
    if not dt.ip4addr(netaddr) or not dt.ip4addr(netmask) then
	return nil
    end

    local netip = netaddr:split('.')
    local netmk = netmask:split('.')

    require "nixio"
    local bit = nixio.bit
    for i=1,4 do netip[i] = bit.band(netip[i], netmk[i]) end

    local newip = { netip[1], netip[2], netip[3], netip[4] }
    for n = user_ip_start, user_ip_max do
	newip[4] = bit.bor(netip[4], n)
	if not string_in_array(table.concat(newip, '.'), usedips) then
	    return table.concat(newip, '.')
	end
    end

    return nil
end

function is_lan_ip(c, ip)
    return is_ip_in_network(ip, 'lan', c)
end

function get_new_ip(lanip, netmask, ip)
    if type(lanip) ~= 'string' or type(netmask) ~= 'string' or type(ip) ~= 'string' then 
       return nil
    end

    local dt = require "luci.cbi.datatypes"
    if not dt.ip4addr(lanip) or not dt.ip4addr(netmask) or not dt.ip4addr(ip) then
       return nil
    end

    local lanips = lanip:split('.')
    local masks = netmask:split('.')
    local ips = ip:split('.')

    require "nixio"
    local bit = nixio.bit
    local newip = { bit.band(lanips[1], masks[1]), bit.band(lanips[2], masks[2]), bit.band(lanips[3], masks[3]), bit.band(lanips[4], masks[4]) }
    local ipmasks = { 255, 255, 255, 255 }
    for i = 1, 4 do
       ipmasks[i] = bit.band(bit.bxor(ipmasks[i], masks[i]), ips[i])
    end

    for i = 1, 4 do
       newip[i] = newip[i] + ipmasks[i]
    end

    return table.concat(newip, '.')
end

local vlan_options = {
    { name = 'lan', id = '1', text = 'LAN' },
    { name = 'guest', id = '3', text = 'Guest', ip = '10.159.157.1', mask = '255.255.255.0' },
    { name = 'x1', id = '4', text = 'X1', ip = '10.159.158.1', mask = '255.255.255.0' },
    { name = 'x2', id = '5', text = 'X2', ip = '10.159.159.1', mask = '255.255.255.0' },
    { name = 'x3', id = '6', text = 'X3', ip = '10.159.160.1', mask = '255.255.255.0' },
}

function get_vlan_list()
    return vlan_options
end

function get_vlan_options()
    local options = {}
    for _, v in ipairs(vlan_options) do
	options[#options+1] = {
	    value = v.id,
	    text = v.text,
	}
    end
    return options
end

function get_vlan_params(name)
    for _, v in ipairs(vlan_options) do
	if name == v.name then
	    return v
	end
    end
    return nil
end

function get_vlan_display_name(name)
    for _, v in ipairs(vlan_options) do
	if v.name == name then
	    return v.text
	end
    end
    return nil
end

function get_vlan_network_name(vlan_id)
    for _, v in ipairs(vlan_options) do
	if v.id == vlan_id then
	    return v.name
	end
    end
    return nil
end

function set_effective_vlan_id(vlan_id, eid)
    for _, v in ipairs(vlan_options) do
	if v.id == vlan_id then
	    v.eid = eid
	    break
	end
    end
end

local function find_vlan_interface_name(c, ifname)
    local network = 'network'
    local nw_name = nil
    c:foreach(network, 'interface', function(i)
	if i.ifname == ifname then
	    nw_name = i['.name']
	    return false
	end
    end)
    return nw_name
end

local function get_lanif_base()
    local ifbase = "eth0"
    local ifname = get_lan_ifname()
    if ifname then
	ifbase = string.match(ifname, '([^.]*)%.?%d?')
    end

    return ifbase
end

function get_canonical_vlan_id(c, eid)
    local ifbase = get_lanif_base()
    local vifname = find_vlan_interface_name(c, ifbase .. '.' .. eid)
    if vifname == nil then
	vifname = find_vlan_interface_name(c, ifbase)
    end

    if vifname == nil then
	return nil
    end

    local p = get_vlan_params(vifname)
    return p ~= nil and p.id or nil
end

function get_lan_ifname(c)
    require "nixio.fs"
    local jsonc = require "luci.jsonc"

    local ifname = "eth0.1"
    local b = jsonc.parse(nixio.fs.readfile("/etc/board.json"))

    if b and b.switch and b.switch.switch0 and b.switch.switch0.roles then
	for _, role in ipairs(b.switch.switch0.roles) do
	    if role.role == 'lan' then
		ifname = role.device
		break
	    end
	end
    end

    return ifname
end

function get_lan_mac()
    local mac
    local f = io.popen('[ -s /sys/class/net/br-lan/address ] && cat /sys/class/net/br-lan/address', 'r')
    if f then
	mac = f:read()
	f:close()
    end

    if #mac == 17 then
	return mac:upper()
    end

    local nw = require "luci.model.network"
    local ntm = nw.init()
    local nets = ntm:get_networks()
    for _, net in ipairs(nets) do
	if net.sid == 'lan' then
	    mac = net:get_interface():mac()
    	    break
	end
    end
    return mac ~= nil and mac:upper() or nil
end

function get_vlan_ifname(c, nw_name)
    local p = get_vlan_params(nw_name)
    if not p then return nil end

    return get_lanif_base() .. '.' .. p.eid
end

local function get_ipset_sectionname_by_name(c, name)
    local firewall = 'firewall'
    local sname = nil
    c:foreach(firewall, 'ipset', function(s)
	if s.name == name then
	    sname = s['.name']
	    return false
	end
    end)
    return sname
end

function update_vpn_guest_fw_rule(c, guests, vpnip, vpnmask)
    local firewall = 'firewall'
    local ipset = get_ipset_sectionname_by_name(c, 'vpnguest')
    if not ipset then
	ipset = c:section(firewall, 'ipset')
	c:set(firewall, ipset, 'enabled', '1')
	c:set(firewall, ipset, 'name', 'vpnguest')
	c:set(firewall, ipset, 'storage', 'hash')
	c:set(firewall, ipset, 'match', 'src_ip')
    end

    local ips = c:get_list(firewall, ipset, 'entry')
    local newips = {}
    for _, ip in ipairs(ips) do
	if not ip_in_network(ip:split('.'), vpnip, vpnmask) then
	    newips[#newips + 1] = ip
	end
    end

    for _, ip in ipairs(guests) do
	newips[#newips + 1] = ip
    end

    if #newips > 0 then c:set_list(firewall, ipset, 'entry', newips) else c:delete_all(firewall, ipset, 'entry') end
end

function update_firewall_lan_ipset(c, ip, is_add)
    local network = 'network'
    local firewall = 'firewall'
    local ipset = get_ipset_sectionname_by_name(c, 'lanips')
    if not ipset then
	ipset = c:section(firewall, 'ipset')
	c:set(firewall, ipset, 'enabled', '1')
	c:set(firewall, ipset, 'name', 'lanips')
	c:set(firewall, ipset, 'storage', 'hash')
	c:set(firewall, ipset, 'match', 'dest_ip')
    end

    local ips = {}
    c:foreach(firewall, 'zone', function(z)
	if z.name ~= 'wan' then
	    local ipaddr = c:get(network, z.name, 'ipaddr')
	    if ipaddr and ipaddr ~= '127.0.0.1' and ipaddr ~= ip then
		ips[#ips+1] = ipaddr
	    end
	end
    end)

    if is_add and ip then ips[#ips+1] = ip end
    c:set_list(firewall, ipset, 'entry', ips)
end

function create_vlan_network(c, nw_name, not_wifi, cfgs)
    local network_cfg = 'network'

    local p = get_vlan_params(nw_name)
    if p == nil then return end

    -- network config
    local iface = nil
    c:foreach(network_cfg, 'interface', function(i)
	if i['.name'] == p.name then
	    iface = i
	    return false
	end
    end)

    if iface ~= nil then return end

    c:section(network_cfg, 'interface', p.name)
    c:set(network_cfg, p.name, 'type', 'bridge')
    c:set(network_cfg, p.name, 'proto', 'static')
    c:set(network_cfg, p.name, 'ipaddr', p.ip)
    c:set(network_cfg, p.name, 'netmask', p.mask)

    add_if_not_exists(cfgs, 'network')

    local dhcp = 'dhcp'
    c:section(dhcp, 'dhcp', p.name)
    c:set(dhcp, p.name, 'interface', p.name)
    c:set(dhcp, p.name, 'dnsmasq_config', 'dnsmasq_lan')
    c:set(dhcp, p.name, 'start', 50)
    c:set(dhcp, p.name, 'limit', 200)
    c:set(dhcp, p.name, 'leasetime', '2h')
    c:set(dhcp, p.name, 'ra', 'disabled')
    c:set(dhcp, p.name, 'dhcpv6', 'disabled')
    c:set_list(dhcp, p.name, 'dhcp_option', '6,'..c:get(network_cfg, 'lan', 'ipaddr'))

    add_if_not_exists(cfgs, dhcp)

    update_firewall_lan_ipset(c, p.ip, true)

    local firewall = 'firewall'
    local gzone = c:section(firewall, 'zone')
    c:set(firewall, gzone, 'name', p.name)
    c:set(firewall, gzone, 'network', p.name)
    c:set(firewall, gzone, 'input', 'ACCEPT')
    c:set(firewall, gzone, 'forward', 'REJECT')
    c:set(firewall, gzone, 'output', 'ACCEPT')

    local forwarding = c:section(firewall, 'forwarding')
    c:set(firewall, forwarding, 'src', p.name)

    local vpnc_ifaces = {}
    for _, iface in ipairs(get_vpn_ifaces(c, 'openvpn')) do
	vpnc_ifaces[iface] = 'vpnc'
    end
    for _, iface in ipairs(get_vpn_ifaces(c, 'wg')) do
	vpnc_ifaces[iface] = 'wgc'
    end

    if vpnc_ifaces[p.name] then
	c:set(firewall, forwarding, 'dest', vpnc_ifaces[p.name])
    else
	c:set(firewall, forwarding, 'dest', 'wan')
    end

    forwarding = c:section(firewall, 'forwarding')
    c:set(firewall, forwarding, 'src', 'lan')
    c:set(firewall, forwarding, 'dest', p.name)

    local z
    local vpn_zones = {}
    c:foreach(firewall, 'zone', function(z)
	if z.name == 'vpn' then
	    if c:get('openvpn', '@server[0]', 'enabled') ~= '0' then
		vpn_zones[#vpn_zones+1] = z
	    end
	elseif z.name == 'wg' then
	    if c:get('wg', '@server[0]', 'enabled') ~= '0' then
		vpn_zones[#vpn_zones+1] = z
	    end
	end
    end)

    for _, z in ipairs(vpn_zones) do
	forwarding = c:section(firewall, 'forwarding')
	c:set(firewall, forwarding, 'src', z.name)
	c:set(firewall, forwarding, 'dest', p.name)
    end

    local rule = c:section(firewall, 'rule')
    c:set(firewall, rule, 'src', p.name)
    c:set(firewall, rule, 'proto', 'tcpudp')
    c:set(firewall, rule, 'dest_port', '53')
    c:set(firewall, rule, 'target', 'ACCEPT')

    -- UDP port 1900 & TCP port 5000 needed by UPnP
    -- We allow UPnP on Guest and X networks
    rule = c:section(firewall, 'rule')
    c:set(firewall, rule, 'src', p.name)
    c:set(firewall, rule, 'proto', 'udp')
    c:set(firewall, rule, 'dest_port', '67 68 1900')
    c:set(firewall, rule, 'target', 'ACCEPT')

    rule = c:section(firewall, 'rule')
    c:set(firewall, rule, 'src', p.name)
    c:set(firewall, rule, 'proto', 'tcp')
    c:set(firewall, rule, 'dest_port', '80 443 5000')
    c:set(firewall, rule, 'target', 'ACCEPT')

    rule = c:section(firewall, 'rule')
    c:set(firewall, rule, 'src', p.name)
    c:set(firewall, rule, 'proto', 'all')
    c:set(firewall, rule, 'family', 'ipv4')
    c:set(firewall, rule, 'ipset', 'lanips')
    c:set(firewall, rule, 'target', 'REJECT')

    add_if_not_exists(cfgs, firewall)
end

function delete_vlan_network(c, nw_name, not_wifi, cfgs)
    local network_cfg = 'network'
    local wireless_cfg = 'wireless'

    local p = get_vlan_params(nw_name)
    if p == nil then return true, false end

    -- network config
    local iface = nil
    c:foreach(network_cfg, 'interface', function(i)
	if i['.name'] == p.name then
	    iface = i
	    return false
	end
    end)

    if iface == nil then
	return true, false
    end

    local gnet = nil
    if not_wifi then -- vlan delete
	c:foreach(wireless_cfg, 'wifi-iface', function(w)
	    if w.network == p.name then
		gnet = w['.name']
		return false
	    end
	end)
    else -- wireless vlan delete
	c:foreach(network_cfg, 'interface', function(v)
	    if v['.name'] == nw_name then
		if v.ifname then gnet = v['.name'] end
		return false
	    end
	end)
    end

    if gnet ~= nil then
	if not_wifi and c:get(network_cfg, p.name, 'ifname') ~= nil then
  	    c:delete(network_cfg, p.name, 'ifname')
	    add_if_not_exists(cfgs, 'network')
	end
	return false
    end

    local hosts_updated = false
    local firewall = 'firewall'
    local dhcp = 'dhcp'
    local fw_delete = {}

    if not not_wifi then -- For network VLAN update, DHCP & redirect are handled in network controller
    	local dhcp_delete = {}
	local new_hosts = {}
	c:foreach(dhcp, 'host', function(d)
	    if is_ip_in_network(d.ip, p.name, c) then
	    	dhcp_delete[#dhcp_delete + 1] = d['.name']
	    else
	    	new_hosts[#new_hosts+1] = d
	    end
	end)

	if #dhcp_delete > 0 then
	    for _, host_entry in ipairs(dhcp_delete) do
	    	c:delete(dhcp, host_entry)
	    end
	    hosts_updated = new_hosts
	end

	c:foreach(firewall, 'redirect', function(r)
	    if r.dest == p.name then
	    	fw_delete[#fw_delete+1] = r['.name']
	    end
	end)
    end

    c:delete(dhcp, p.name)
    add_if_not_exists(cfgs, dhcp)

    c:foreach(firewall, 'zone', function(z)
    	if z.network == p.name then
    	    fw_delete[#fw_delete+1] = z['.name']
    	end
    end)

    c:foreach(firewall, 'forwarding', function(f)
    	if f.src == p.name or f.dest == p.name then
    	    fw_delete[#fw_delete+1] = f['.name']
    	end
    end)

    c:foreach(firewall, 'rule', function(r)
    	if r.src == p.name or r.dest == p.name then
    	    fw_delete[#fw_delete+1] = r['.name']
    	end
    end)

    for _, d in ipairs(fw_delete) do
	c:delete(firewall, d)
    end

    update_firewall_lan_ipset(c, p.ip, false)

    add_if_not_exists(cfgs, firewall)

    c:delete(network_cfg, p.name)
    add_if_not_exists(cfgs, 'network')

    local upnpd = 'upnpd'
    local upnp_enabled = is_upnpd_enabled(c)
    local upnpd_ifaces = c:get(upnpd, 'config', 'internal_iface')
    if upnpd_ifaces ~= nil then
    	local ifaces = {}
    	upnpd_ifaces = upnpd_ifaces:split(' ')
    	for _, iface in ipairs(upnpd_ifaces) do
    	    if iface ~= p.name then
    		ifaces[#ifaces+1] = iface
    	    end
    	end

    	if #upnpd_ifaces ~= #ifaces then
    	    if #ifaces > 0 then
    		c:set(upnpd, 'config', 'internal_iface', table.concat(ifaces, ' '))
    	    else
    		if upnp_enabled then
    		    require "luci.sys"
    		    luci.sys.init.stop('miniupnpd')
    		    luci.sys.init.disable('miniupnpd')
    		end
    	    end

    	    if upnp_enabled then
    		add_if_not_exists(cfgs, upnpd)
    	    end
    	end
    end

    return gnet == nil, hosts_updated
end

function is_upnpd_enabled(c)
    local fs = require "nixio.fs"
    if not fs.access("/etc/init.d/miniupnpd") then
	return false
    end

    require "luci.sys"
    return luci.sys.init.enabled('miniupnpd') and c:get('upnpd', 'config', 'enabled') ~= '0'
end

function get_internal_interfaces(c)
    local network = 'network'
    local internal_ifs = {}
    for _, v in ipairs(vlan_options) do
	c:foreach(network, 'interface', function(i)
	    if i['.name'] == v.name then
	    	internal_ifs[#internal_ifs+1] = {
		    name = v.name,
		    text = v.text,
	        }
		return false
	    end
	end)
    end
    return internal_ifs
end

function get_vpn_ifaces(c, vpn_name)
    local vpn_ifaces = 'vpn-ifaces'
    local ifaces = {}
    c:foreach(vpn_ifaces, 'vpn-iface', function(s)
	if s.vpn == vpn_name then
	    ifaces[#ifaces+1] = s.iface
	end
    end)
    return ifaces
end

function set_vpn_ifaces(c, vpn_name, ifaces, cfgs)
    local vpn_ifaces = 'vpn-ifaces'
    local dhcp = 'dhcp'
    local vpnifcs = {}

    c:foreach(vpn_ifaces, 'vpn-iface', function(s)
	if s.vpn == vpn_name then
	    if not remove_string_from_array(ifaces, s.iface) then
		vpnifcs[#vpnifcs + 1] = s['.name']
	    end
	elseif string_in_array(s.iface, ifaces) then
	    vpnifcs[#vpnifcs + 1] = s['.name']
	end
    end)

    if #vpnifcs > 0 then
	for _, ifc in ipairs(vpnifcs) do
	    c:delete(vpn_ifaces, ifc)
	end
    end

    if ifaces ~= nil and #ifaces > 0 then
	for _, iface in ipairs(ifaces) do
	    local s = c:section(vpn_ifaces, 'vpn-iface')
	    c:set(vpn_ifaces, s, 'vpn', vpn_name)
	    c:set(vpn_ifaces, s, 'iface', iface)
	end
	c:set(dhcp, 'dnsmasq_lan', 'resolvfile', '/tmp/resolv.conf.'..vpn_name)
    elseif #vpnifcs > 0 then
	c:set(dhcp, 'dnsmasq_lan', 'resolvfile', '/tmp/resolv.conf.auto')
    end
    c:commit(dhcp)

    return c:commit(vpn_ifaces)
end

function update_firewall_rules_for_vpns(c, vpn_name, enable)
    local firewall = 'firewall'

    local zones, vpn_zone

    zones = {}
    c:foreach(firewall, 'zone', function(z)
	if z.name == vpn_name then
	    vpn_zone = z
	elseif not z.name:starts('vpn') and not z.name:starts('wg') then
	    zones[#zones+1] = z
	end
    end)

    if enable then
	if not vpn_zone then
	    vpn_zone = c:section(firewall, 'zone')
	    c:set(firewall, vpn_zone, 'name', vpn_name)
	    c:set_list(firewall, vpn_zone, 'network', vpn_name)
	    c:set(firewall, vpn_zone, 'input', 'ACCEPT')
	    c:set(firewall, vpn_zone, 'output', 'ACCEPT')
	    c:set(firewall, vpn_zone, 'forward', 'REJECT')
	end

	local dsts = {}
	c:foreach(firewall, 'forwarding', function(fwd)
	    if fwd.src == vpn_name then
		dsts[#dsts+1] = fwd.dest
	    end
	end)

	for _, zone in ipairs(zones) do
	    if not string_in_array(zone.name, dsts) then
		local fwd = c:section(firewall, 'forwarding')
		c:set(firewall, fwd, 'src', vpn_name)
		c:set(firewall, fwd, 'dest', zone.name)
	    end
	end
    else
	if vpn_zone then
	    c:delete(firewall, vpn_zone['.name'])
	end

	local fwds = {}
	c:foreach(firewall, 'forwarding', function(fwd)
	    if fwd.src == vpn_name then
		fwds[#fwds+1] = fwd['.name']
	    end
	end)

	for _, fwd in ipairs(fwds) do
	    c:delete(firewall, fwd)
	end
    end
end

function update_firewall_rules_for_vpnc(c, vpn_name, dest)
    local firewall = 'firewall'
    local vpn_ifaces = 'vpn-ifaces'

    local internal_ifs = get_vpn_ifaces(c, vpn_name)
    local iifaces = {}
    local vpnc_ifs = {}

    for _, iface in ipairs(get_internal_interfaces(c)) do
	iifaces[#iifaces+1] = iface.name
	if #internal_ifs > 0 then
	    vpnc_ifs[#vpnc_ifs+1] = {
		name = iface.name
	    }
	end
    end

    local update_needed = false
    c:foreach(firewall, 'forwarding', function(fwd)
	if fwd.dest == dest then
	    local forwarded = false
	    for _, ifs in ipairs(vpnc_ifs) do
		if fwd.src == ifs.name then
		    forwarded = true
		    ifs.forwarded = true
		    break
		end
	    end
	    if not forwarded then
		update_needed = true
	    end
	end
    end)

    if not update_needed then
	for _, ifs in ipairs(vpnc_ifs) do
	    if not ifs.forwarded then
		update_needed = true
		break
	    end
	end
    end

    local updated = false
    if update_needed then
	c:foreach(firewall, 'forwarding', function(fwd)
	    if string_in_array(fwd.src, iifaces) then
		local fwan = true
		for _, ifs in ipairs(vpnc_ifs) do
		    if fwd.src == ifs.name and string_in_array(fwd.dest, { 'wan', 'vpnc', 'wgc' }) then
			if fwd.dest ~= dest then
			    c:set(firewall, fwd['.name'], 'dest', dest)
			end
			fwan = false
			break
		    end
		end

		if fwan and fwd.dest == dest and dest ~= 'wan' then
		    c:set(firewall, fwd['.name'], 'dest', 'wan')
		end
	    end
	end)
	updated = true
    end

    if updated then
	updated = c:commit(firewall)
    end

    return updated
end

function random_string(cs, length, group_size)
    local fs = require "nixio.fs"
    local rand = fs.readfile("/dev/urandom", length)
    local i, s, max = 1, '', #cs

    group_size = type(group_size) == 'number' and group_size or 0
    while i <= length do
	local idx = (rand:byte(i) % max) + 1
	s = s .. cs:sub(idx, idx)
	if group_size > 0 and i > 0 and i < length and i % group_size == 0 then
	    s = s .. '-'
	end
	i = i + 1
    end
    return s
end

function save_tmp_data(key, value)
    local jsonc = require "luci.jsonc"
    require "nixio.fs".writefile(string.format('/tmp/log/%s.json', key), jsonc.stringify(value))
end

function get_tmp_data(key)
    local r
    local jsonc = require "luci.jsonc"
    local s = require "nixio.fs".readfile(string.format("/tmp/log/%s.json", key))
    if s then r = jsonc.parse(s) end
    return r and r or {}
end
