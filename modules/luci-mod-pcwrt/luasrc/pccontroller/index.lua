local http = require "luci.http"
local util = require "luci.util"
local status = require "luci.tools.status"
local i18n = require "luci.i18n"

module("luci.pccontroller.index", package.seeall)

function index()
    http.redirect(build_url('status'))
end
